// SPDX-License-Identifier: GPL-2.0-only
//
//! Filesystem mount dispatcher.
//!
//! The POSIX personality decodes the public wire message and
//! resolves the target vnode. This module owns the mount-kind
//! dispatch so filesystem-specific setup stays with filesystem
//! clients. Adding ext4 / FAT / NTFS should mean adding a client
//! module and one branch here, not teaching the POSIX handler about
//! backend feature negotiation, SHM rings, or root-vnode layout.

use crate::core::error::VfsError;
use crate::core::mount::{Mount, MountHandle, MountKind};
use crate::core::vnode::VnodeHandle;
use crate::core::vop::VfsOps;
use crate::core::vop_context::OwnerMountCtx;
use crate::ops::CaseFoldPolicy;
use crate::owner::VfsState;
use crate::personality::wire::{send_reply_err_for_client, send_reply_ok_for_client};
use crate::server::types::ClientHandle;

pub(crate) fn case_fold_for_flags(flags: u64) -> CaseFoldPolicy {
    if flags & trona_protocol::posix::VFS_MOUNT_FLAG_CASEFOLD != 0 {
        CaseFoldPolicy::InsensitivePreserving
    } else {
        CaseFoldPolicy::Sensitive
    }
}

pub(crate) unsafe fn begin_mount(
    state: &mut VfsState,
    client: ClientHandle,
    target_vh: VnodeHandle,
    kind: MountKind,
    flags: u64,
    mount_path: &[u8],
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        match kind {
            MountKind::SaltyFs => {
                crate::fs::saltyfs_client::vfsops::begin_mount(
                    state,
                    client,
                    target_vh,
                    flags,
                    mount_path,
                    reply_lease,
                );
            }
            MountKind::Inet => {
                begin_inet_mount(state, client, target_vh, flags, mount_path, reply_lease);
            }
            MountKind::Pty => {
                begin_pty_mount(state, client, target_vh, flags, mount_path, reply_lease);
            }
            MountKind::Fb => {
                begin_fb_mount(state, client, target_vh, flags, mount_path, reply_lease);
            }
            _ => {
                finish_inmemory_mount(
                    state,
                    client,
                    target_vh,
                    kind,
                    flags,
                    mount_path,
                    reply_lease,
                );
            }
        }
    }
}

/// Stamp a freshly-mounted default service backend into one of the
/// path-less syscall registries (`socket(AF_INET, ...)`,
/// `posix_openpt`, framebuffer device access).
type DefaultMountSetter = fn(&mut VfsState, MountHandle);

fn set_default_inet_mount(state: &mut VfsState, mh: MountHandle) {
    state.default_inet_mount = mh;
}

fn set_default_pty_mount(state: &mut VfsState, mh: MountHandle) {
    state.default_pty_mount = mh;
}

fn set_default_fb_mount(state: &mut VfsState, mh: MountHandle) {
    state.default_fb_mount = mh;
}

/// Common path for service-backed pseudo mounts (inet / pty / fb):
/// resolve the service via namesrv, negotiate a backend session,
/// splice the mount into the namespace, and stamp the default
/// service registry. Real filesystem clients should keep their own
/// mount negotiation in their `fs::<driver>_client` module.
unsafe fn begin_service_mount(
    state: &mut VfsState,
    client: ClientHandle,
    target_vh: VnodeHandle,
    kind: MountKind,
    flags: u64,
    mount_path: &[u8],
    reply_lease: trona_server::ReplyLease,
    backend_name: &[u8],
    completion_fn: crate::owner::session::CompletionFn,
    set_default: DefaultMountSetter,
) {
    let Some(backend_ep) =
        trona_runtime::client::lazy_resolve::namesrv_lookup_blocking(backend_name)
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
        mount.kind = kind;
        mount.fs_instance_id = fs_id;
        mount.mount_flags = flags;
        mount.case_fold = case_fold_for_flags(flags);
        mount.set_mount_path(mount_path);
    }
    let mount_handle_raw = mount_handle_to_raw(mount_h);

    let outcome = match unsafe {
        crate::owner::session::attach_backend_session(
            state,
            backend_ep,
            fs_id,
            mount_handle_raw,
            flags,
            completion_fn,
            None,
            None,
            None,
        )
    } {
        Ok(o) => o,
        Err(e) => {
            // `backend_ep` was moved into attach_backend_session, which frees it
            // on its own failure paths; nothing to release here.
            state.mounts.release(mount_h);
            send_reply_err_for_client(state, client, reply_lease, e);
            return;
        }
    };

    if let Some(mount) = state.mounts.get_mut(mount_h) {
        mount.backend_session_idx = outcome.slot_idx;
    }

    if let Err(e) =
        unsafe { crate::core::mount_ctl::finalize_mount_tail(state, mount_h, target_vh, fs_id) }
    {
        crate::owner::session::tear_down(state, outcome.slot_idx);
        state.mounts.release(mount_h);
        send_reply_err_for_client(state, client, reply_lease, e);
        return;
    }
    unsafe {
        crate::boot::late_mount::on_mount_finalized(state, mount_h, target_vh);
    }

    set_default(state, mount_h);
    send_reply_ok_for_client(state, client, reply_lease, &[fs_id.0]);
}

#[inline]
fn mount_handle_to_raw(mh: MountHandle) -> u64 {
    ((mh.slot() as u64) << 32) | (mh.epoch() as u64)
}

/// Inet mount — backend resolved via `namesrv_lookup("netsrv")`.
unsafe fn begin_inet_mount(
    state: &mut VfsState,
    client: ClientHandle,
    target_vh: VnodeHandle,
    flags: u64,
    mount_path: &[u8],
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        begin_service_mount(
            state,
            client,
            target_vh,
            MountKind::Inet,
            flags,
            mount_path,
            reply_lease,
            b"netsrv",
            crate::owner::net_completion::netsrv_completion,
            set_default_inet_mount,
        );
    }
}

/// PTY mount — backend resolved via `namesrv_lookup("posix_ttysrv")`.
unsafe fn begin_pty_mount(
    state: &mut VfsState,
    client: ClientHandle,
    target_vh: VnodeHandle,
    flags: u64,
    mount_path: &[u8],
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        begin_service_mount(
            state,
            client,
            target_vh,
            MountKind::Pty,
            flags,
            mount_path,
            reply_lease,
            b"posix_ttysrv",
            crate::owner::pty_completion::pty_completion,
            set_default_pty_mount,
        );
    }
}

/// Framebuffer mount — backend resolved via `namesrv_lookup("dispdrv")`.
unsafe fn begin_fb_mount(
    state: &mut VfsState,
    client: ClientHandle,
    target_vh: VnodeHandle,
    flags: u64,
    mount_path: &[u8],
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        begin_service_mount(
            state,
            client,
            target_vh,
            MountKind::Fb,
            flags,
            mount_path,
            reply_lease,
            b"dispdrv",
            crate::owner::fb_completion::fb_completion,
            set_default_fb_mount,
        );
    }
}

fn vfsops_for(kind: MountKind) -> Option<&'static VfsOps> {
    let p: *const VfsOps = match kind {
        MountKind::Initrd | MountKind::Ramfs => &crate::fs::ramfs::RAMFS_VFSOPS,
        MountKind::Tmpfs => &crate::fs::tmpfs::TMPFS_VFSOPS,
        MountKind::Devfs => &crate::fs::devfs::DEVFS_VFSOPS,
        MountKind::Procfs => &crate::fs::procfs::PROCFS_VFSOPS,
        MountKind::Sysctlfs => &crate::fs::sysctlfs::SYSCTLFS_VFSOPS,
        MountKind::Pipefs => &crate::fs::pipefs::PIPEFS_VFSOPS,
        MountKind::SaltyFs
        | MountKind::Inet
        | MountKind::Pty
        | MountKind::Fb
        | MountKind::Empty => return None,
    };
    Some(unsafe { &*p })
}

pub(crate) unsafe fn mount_inmemory_boot(
    state: &mut VfsState,
    target_vh: VnodeHandle,
    kind: MountKind,
    flags: u64,
    mount_path: &[u8],
) -> Result<MountHandle, VfsError> {
    let vfsops_ptr: *const VfsOps = match vfsops_for(kind) {
        Some(p) => p,
        None => return Err(VfsError::Inval),
    };

    let mount_h = state.mounts.alloc().ok_or(VfsError::NoMem)?;
    let fs_id = state.next_fs_instance_id();
    if let Some(mount) = state.mounts.get_mut(mount_h) {
        *mount = Mount::EMPTY;
        mount.kind = kind;
        mount.fs_instance_id = fs_id;
        mount.vfsops = vfsops_ptr;
        mount.mount_flags = flags;
        mount.case_fold = case_fold_for_flags(flags);
        mount.set_mount_path(mount_path);
    }

    let root_vh = unsafe {
        let mut mctx = match OwnerMountCtx::from_state(state, mount_h) {
            Some(c) => c,
            None => {
                state.mounts.release(mount_h);
                return Err(VfsError::Io);
            }
        };
        match ((*vfsops_ptr).mount)(&mut mctx) {
            Ok(h) => h,
            Err(e) => {
                state.mounts.release(mount_h);
                return Err(e);
            }
        }
    };

    if let Some(mount) = state.mounts.get_mut(mount_h) {
        mount.root = root_vh;
    }

    if let Err(e) =
        unsafe { crate::core::mount_ctl::finalize_mount_tail(state, mount_h, target_vh, fs_id) }
    {
        unsafe {
            if let Some(mut mctx) = OwnerMountCtx::from_state(state, mount_h) {
                let _ = ((*vfsops_ptr).unmount)(&mut mctx);
            }
        }
        state.mounts.release(mount_h);
        return Err(e);
    }
    unsafe {
        crate::core::mount_ctl::refresh_global_ns(state);
        crate::boot::late_mount::on_mount_finalized(state, mount_h, target_vh);
    }
    Ok(mount_h)
}

unsafe fn finish_inmemory_mount(
    state: &mut VfsState,
    client: ClientHandle,
    target_vh: VnodeHandle,
    kind: MountKind,
    flags: u64,
    mount_path: &[u8],
    reply_lease: trona_server::ReplyLease,
) {
    let vfsops_ptr: *const VfsOps = match vfsops_for(kind) {
        Some(p) => p,
        None => {
            send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
            return;
        }
    };

    let mount_h = match state.mounts.alloc() {
        Some(h) => h,
        None => {
            send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
            return;
        }
    };

    let fs_id = state.next_fs_instance_id();
    if let Some(mount) = state.mounts.get_mut(mount_h) {
        *mount = Mount::EMPTY;
        mount.kind = kind;
        mount.fs_instance_id = fs_id;
        mount.vfsops = vfsops_ptr;
        mount.mount_flags = flags;
        mount.case_fold = case_fold_for_flags(flags);
        mount.set_mount_path(mount_path);
    }

    let root_vh = unsafe {
        let mut mctx = match OwnerMountCtx::from_state(state, mount_h) {
            Some(c) => c,
            None => {
                state.mounts.release(mount_h);
                send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
                return;
            }
        };
        match ((*vfsops_ptr).mount)(&mut mctx) {
            Ok(h) => h,
            Err(e) => {
                state.mounts.release(mount_h);
                send_reply_err_for_client(state, client, reply_lease, e);
                return;
            }
        }
    };

    if let Some(mount) = state.mounts.get_mut(mount_h) {
        mount.root = root_vh;
    }

    if let Err(e) =
        unsafe { crate::core::mount_ctl::finalize_mount_tail(state, mount_h, target_vh, fs_id) }
    {
        unsafe {
            let mut mctx = match OwnerMountCtx::from_state(state, mount_h) {
                Some(c) => c,
                None => {
                    state.mounts.release(mount_h);
                    send_reply_err_for_client(state, client, reply_lease, e);
                    return;
                }
            };
            let _ = ((*vfsops_ptr).unmount)(&mut mctx);
        }
        state.mounts.release(mount_h);
        send_reply_err_for_client(state, client, reply_lease, e);
        return;
    }
    unsafe {
        crate::boot::late_mount::on_mount_finalized(state, mount_h, target_vh);
    }

    send_reply_ok_for_client(state, client, reply_lease, &[fs_id.0]);
}
