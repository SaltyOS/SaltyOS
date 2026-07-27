// SPDX-License-Identifier: GPL-2.0-only
//
//! devfs `VopVector` — per-device routing for the synthetic
//! `/dev` namespace.
//!
//! `lookup` walks the static registration table for the root
//! directory and the dynamic per-PTY entries for the `pts/`
//! subdirectory. Character devices route `read` / `write` per
//! `DevKind`:
//!
//! - `Null` — read returns 0 (EOF), write drops.
//! - `Zero` — read fills with zeros, write drops.
//! - `Urandom` — read fills from the caller-visible `KernelRng` cap.
//! - `Console` — write forwards to substrate's serial sink; read
//!   returns 0.
//! - `Tty` / `Ptmx` / `PtySlave` — routed through
//!   `posix_ttysrv` by the POSIX device layer.
//! - `Fb0` — routed through the POSIX device layer to dispdrv.

use crate::core::cred::VfsCred;
use crate::core::error::VfsError;
use crate::core::file::{VAttr, VStatfs};
use crate::core::outcome::{Parked, Ready, VopOutcome};
use crate::core::vnode::{VnodeHandle, VnodeKind};
use crate::core::vop::ReaddirEmit;
use crate::core::vop_context::{OwnerVopCtx, VopDataCtx};

use super::{DEVFS_REGISTRATIONS, DevKind, DevfsMountData, DevfsVnodeData};

#[inline]
unsafe fn vdata(ctx: &OwnerVopCtx<'_>) -> *mut DevfsVnodeData {
    ctx.data as *mut DevfsVnodeData
}

#[inline]
unsafe fn vdata_d(ctx: &VopDataCtx) -> *mut DevfsVnodeData {
    ctx.data as *mut DevfsVnodeData
}

#[inline]
unsafe fn mdata(ctx: &OwnerVopCtx<'_>) -> *mut DevfsMountData {
    ctx.mount_data as *mut DevfsMountData
}

#[inline]
unsafe fn mdata_d(ctx: &VopDataCtx) -> *mut DevfsMountData {
    ctx.mount_data as *mut DevfsMountData
}

fn name_eq(a: *const u8, a_len: u8, b: &[u8]) -> bool {
    if a_len as usize != b.len() {
        return false;
    }
    for i in 0..a_len as usize {
        if unsafe { *a.add(i) } != b[i] {
            return false;
        }
    }
    true
}

unsafe fn lookup_handle_by_id(md: *const DevfsMountData, id: u64) -> VnodeHandle {
    unsafe {
        for i in 0..(*md).count {
            if (*md).vnode_ids[i] == id {
                return (*md).vnode_handles[i];
            }
        }
        VnodeHandle::INVALID
    }
}

// =========================================================================
// MetaOps
// =========================================================================

pub(crate) unsafe fn devfs_lookup(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let dir_vdata = vdata(ctx);
        if dir_vdata.is_null() {
            return Err(VfsError::Io);
        }
        if (*dir_vdata).kind != DevKind::PtsDir && (*ctx.vnode).kind != VnodeKind::Directory {
            return Err(VfsError::NotDir);
        }
        if name_len == 1 && *name == b'.' {
            return Ok(Ready(ctx.handle));
        }
        if name_len == 2 && *name == b'.' && *name.add(1) == b'.' {
            // Both `/dev` and `/dev/pts` map `..` to themselves
            // until the cross-mount walk reaches in.
            return Ok(Ready(ctx.handle));
        }

        let md = mdata(ctx);

        // /dev (root) — match against `DEVFS_REGISTRATIONS` plus
        // the synthetic `pts` directory.
        if (*dir_vdata).kind != DevKind::PtsDir {
            for reg in DEVFS_REGISTRATIONS {
                if name_eq(name, name_len, reg.name) {
                    let mut id: u64 = 1;
                    for r in DEVFS_REGISTRATIONS {
                        if ::core::ptr::eq(r as *const _, reg as *const _) {
                            return Ok(Ready(lookup_handle_by_id(md, id)));
                        }
                        id += 1;
                    }
                }
            }
            if name_eq(name, name_len, b"pts") {
                let pts_id = 1 + DEVFS_REGISTRATIONS.len() as u64;
                return Ok(Ready(lookup_handle_by_id(md, pts_id)));
            }
            return Ok(Ready(VnodeHandle::INVALID));
        }

        // /dev/pts/0 — console PTY slave. Additional PTY slaves
        // will be registered into devfs when the allocation
        // callback path grows a VFS-side notification.
        if name_eq(name, name_len, b"0") {
            let pty0_id = 2 + DEVFS_REGISTRATIONS.len() as u64;
            return Ok(Ready(lookup_handle_by_id(md, pty0_id)));
        }
        Ok(Ready(VnodeHandle::INVALID))
    }
}

pub(crate) unsafe fn devfs_open(ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    unsafe {
        let vdata = vdata(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        match (*vdata).kind {
            DevKind::Console
            | DevKind::Null
            | DevKind::Zero
            | DevKind::Urandom
            | DevKind::Ptmx
            | DevKind::Tty
            | DevKind::PtySlave
            | DevKind::Fb0
            | DevKind::PtsDir => Ok(Ready(())),
        }
    }
}

pub(crate) unsafe fn devfs_close(_ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    Ok(Ready(()))
}

pub(crate) unsafe fn devfs_getattr(ctx: &mut OwnerVopCtx<'_>, attr: *mut VAttr) -> VopOutcome<()> {
    unsafe {
        let vdata = vdata(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        let fs_id = (*ctx.mount).fs_instance_id;
        (*attr).fs_instance_id = fs_id;
        (*attr).backend_node_id = (*ctx.vnode).id();
        (*attr).backend_seq = 0;
        (*attr).kind = (*ctx.vnode).kind;
        (*attr).mode = (*vdata).mode;
        (*attr).uid = 0;
        (*attr).gid = 0;
        (*attr).nlink = (*ctx.vnode).nlink;
        (*attr).size = 0;
        (*attr).blocks = 0;
        (*attr).atime = 0;
        (*attr).mtime = 0;
        (*attr).ctime = 0;
        Ok(Ready(()))
    }
}

pub(crate) unsafe fn devfs_access(
    _ctx: &mut OwnerVopCtx<'_>,
    _mode: u32,
    _cred: *const VfsCred,
) -> VopOutcome<()> {
    Ok(Ready(()))
}

pub(crate) unsafe fn devfs_inactive(ctx: &mut OwnerVopCtx<'_>) -> VopOutcome<()> {
    unsafe {
        crate::owner::pager_rpc::release_mo_binding_for_vnode(ctx.state, ctx.handle);
    }
    Ok(Ready(()))
}

// =========================================================================
// DataOps
// =========================================================================

pub(crate) unsafe fn devfs_read(
    ctx: &VopDataCtx,
    _offset: u64,
    dst: *mut u8,
    len: u64,
) -> VopOutcome<u64> {
    unsafe {
        let vdata = vdata_d(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        match (*vdata).kind {
            DevKind::Null => Ok(Ready(0)),
            DevKind::Zero => {
                ::core::ptr::write_bytes(dst, 0, len as usize);
                Ok(Ready(len))
            }
            DevKind::Urandom => {
                let r = trona_kernel::syscall::rng_read_bytes(
                    trona_runtime::client::caps::kernel_rng_cap().addr(),
                    dst,
                    len as usize,
                );
                if r.error != 0 {
                    return Err(VfsError::Io);
                }
                Ok(Ready(r.value))
            }
            DevKind::Console => Ok(Ready(0)),
            DevKind::Fb0 | DevKind::Ptmx | DevKind::Tty | DevKind::PtySlave => {
                Err(VfsError::NotSup)
            }
            DevKind::PtsDir => Err(VfsError::IsDir),
        }
    }
}

pub(crate) unsafe fn devfs_write(
    ctx: &VopDataCtx,
    _offset: u64,
    src: *const u8,
    len: u64,
) -> VopOutcome<u64> {
    unsafe {
        let vdata = vdata_d(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        match (*vdata).kind {
            DevKind::Null | DevKind::Zero => Ok(Ready(len)),
            DevKind::Console => {
                // Forward to substrate's serial sink. The full
                // console subsystem registration lands with the
                // console personality; this immediate path keeps
                // boot-time `printf` traffic visible while the
                // wire is being built.
                for i in 0..len as usize {
                    let b = *src.add(i);
                    trona_runtime::debug::serial::serial_putc(b);
                }
                Ok(Ready(len))
            }
            DevKind::Urandom => Err(VfsError::Inval),
            DevKind::Fb0 | DevKind::Ptmx | DevKind::Tty | DevKind::PtySlave => {
                Err(VfsError::NotSup)
            }
            DevKind::PtsDir => Err(VfsError::IsDir),
        }
    }
}

/// Device ioctl entry. tty-class devices (`/dev/console`, tty, ptmx,
/// pts/N) route to posix_ttysrv; the framebuffer routes to dispdrv.
/// Both park a `PendingOp` and the completion router projects the
/// backend reply into the per-command POSIX shape — this is the single
/// async ioctl path (no per-device special-casing in the personality
/// layer). `null` / `zero` / `urandom` vend no ioctls.
pub(crate) unsafe fn devfs_ioctl(
    ctx: &VopDataCtx,
    cmd: u32,
    arg: u64,
) -> crate::core::vop::IoctlResult {
    unsafe {
        let vdata = vdata_d(ctx);
        if vdata.is_null() {
            return Err(VfsError::NotSup);
        }
        let Some(state) = ctx.state_mut() else {
            return Err(VfsError::Io);
        };
        let pty_id = match (*vdata).kind {
            // `/dev/tty` routes to the caller session's bound ctty pty
            // (resolved at open); falls back to pty0 when unbound.
            DevKind::Tty => Some(
                ctx.open_object
                    .and_then(|h| state.open_objects.get(h))
                    .map(|o| o.ctty_pty)
                    .filter(|&p| p != u32::MAX)
                    .unwrap_or(0),
            ),
            DevKind::Console | DevKind::Ptmx => Some(0u32),
            DevKind::PtySlave => Some((*vdata).sub_id),
            _ => None,
        };
        if let Some(pty_id) = pty_id {
            // ctty-control ioctls are keyed by posix_ttysrv on the caller's
            // POSIX session (TIOCSCTTY / TIOCSPGRP / TIOCGSID / TIOCNOTTY).
            // Only init knows the session, so resolve it asynchronously
            // (park on init) and re-issue the pty ioctl at finalize — a
            // blocking VFS→init query here would risk the init↔VFS reactor
            // cycle. These cmds are POSIX-only, so the reply is `PosixIoctl`.
            let needs_session = matches!(
                cmd as u64,
                trona_protocol::posix_abi::tty::TIOCSCTTY
                    | trona_protocol::posix_abi::tty::TIOCSPGRP
                    | trona_protocol::posix_abi::tty::TIOCGSID
                    | trona_protocol::posix_abi::tty::TIOCNOTTY
            );
            if needs_session {
                // `FillIoctlReply` needs the vnode key; resolve it from the
                // vop's vnode handle. The `client` handle is injected by
                // `do_ioctl_from_fd` (the dispatch layer that holds it) when
                // it attaches the reply lease.
                let vkey = {
                    let Some(meta) =
                        crate::core::vop_context::OwnerVopCtx::from_state(state, ctx.vnode_handle)
                    else {
                        return Err(VfsError::Io);
                    };
                    (*meta.vnode).key
                };
                let plan = [crate::owner::init_rpc::InitStep {
                    label: trona_protocol::posix::INIT_PGRP_SESSION,
                    sub_op: trona_protocol::posix::INIT_PGRP_SUB_GET_SID_PGID_BY_BADGE,
                    arg: ctx.caller_badge,
                }];
                return match crate::owner::init_rpc::begin_init_read_deferred(
                    state,
                    &plan,
                    crate::owner::init_rpc::InitReadState::Ctty {
                        client: crate::server::types::ClientHandle::INVALID,
                        action: crate::owner::init_rpc::CttyAction::Ioctl {
                            pty_id,
                            cmd,
                            arg,
                            vkey,
                            reply: crate::ops::IoctlReplyIntent::PosixIoctl,
                        },
                        sid: 0,
                        pgid: 0,
                    },
                    0,
                    ctx.caller_badge,
                ) {
                    Some(handle) => Ok(Parked(handle)),
                    None => Err(VfsError::Io),
                };
            }
            return match crate::personality::posix::device::issue_pty_ioctl(
                state, pty_id, cmd, arg, 0, 0,
            ) {
                Ok(handle) => Ok(Parked(handle)),
                Err(e) => Err(e),
            };
        }
        // Framebuffer ioctls keep their dedicated path in the
        // personality layer (`handle_fb_ioctl_for_fd`): fb's reply
        // protocol returns raw display dimensions for the client to
        // assemble into `fb_var_screeninfo` / `fb_fix_screeninfo`,
        // which is incompatible with the generic struct-bytes ioctl
        // reply shape. devfs unifies only the tty-class ioctls here.
        Err(VfsError::NotSup)
    }
}

pub(crate) unsafe fn devfs_readdir(
    ctx: &VopDataCtx,
    cookie: *mut u64,
    emit: ReaddirEmit<'_>,
) -> VopOutcome<()> {
    unsafe {
        let vdata = vdata_d(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        // Only `pts/` and the root directory carry directory
        // semantics. Every other DevKind is a leaf char device.
        if !matches!((*vdata).kind, DevKind::PtsDir) && ctx.vtype != VnodeKind::Directory as u8 {
            return Err(VfsError::NotDir);
        }

        let mut pos = *cookie;
        let attr = VAttr::zeroed();

        if pos == 0 {
            if !emit(ctx.id, b".".as_ptr(), 1, 4, &attr) {
                *cookie = pos + 1;
                return Ok(Ready(()));
            }
            pos += 1;
        }
        if pos == 1 {
            if !emit(ctx.id, b"..".as_ptr(), 2, 4, &attr) {
                *cookie = pos + 1;
                return Ok(Ready(()));
            }
            pos += 1;
        }

        // Root only: enumerate static device names + pts.
        if (*vdata).kind != DevKind::PtsDir {
            let base = 2u64;
            let mut idx = 0u64;
            for reg in DEVFS_REGISTRATIONS {
                let entry_pos = base + idx;
                if pos > entry_pos {
                    idx += 1;
                    continue;
                }
                // DT_CHR = 2.
                let id = idx + 1;
                if !emit(id, reg.name.as_ptr(), reg.name.len() as u8, 2, &attr) {
                    *cookie = entry_pos + 1;
                    return Ok(Ready(()));
                }
                pos = entry_pos + 1;
                idx += 1;
            }
            let pts_pos = base + idx;
            if pos <= pts_pos {
                let pts_id = 1 + DEVFS_REGISTRATIONS.len() as u64;
                // DT_DIR = 4.
                if !emit(pts_id, b"pts".as_ptr(), 3, 4, &attr) {
                    *cookie = pts_pos + 1;
                    return Ok(Ready(()));
                }
                pos = pts_pos + 1;
            }
        }
        // PtsDir: PTY 0 is the boot console PTY; further slaves
        // arrive through the future registration path.
        let _ = mdata_d(ctx);
        if (*vdata).kind == DevKind::PtsDir {
            let entry_pos = 2u64;
            if pos <= entry_pos
                && !emit(
                    2 + DEVFS_REGISTRATIONS.len() as u64,
                    b"0".as_ptr(),
                    1,
                    2,
                    &attr,
                )
            {
                *cookie = entry_pos + 1;
                return Ok(Ready(()));
            }
            pos = entry_pos + 1;
        }

        *cookie = pos;
        Ok(Ready(()))
    }
}

pub(crate) unsafe fn devfs_statfs(ctx: &VopDataCtx, out: *mut VStatfs) -> VopOutcome<()> {
    unsafe {
        let md = mdata_d(ctx);
        (*out).bsize = 4096;
        (*out).frsize = 4096;
        (*out).blocks = 0;
        (*out).bfree = 0;
        (*out).bavail = 0;
        (*out).files = (*md).count as u64;
        (*out).ffree = (super::MAX_DEVFS_VNODES - (*md).count) as u64;
        (*out).favail = (*out).ffree;
        (*out).fsid = ctx.fs_instance_id.0;
        (*out).flag = 0;
        (*out).namemax = 255;
        (*out).set_fs_name(b"devfs");
        Ok(Ready(()))
    }
}
