// SPDX-License-Identifier: GPL-2.0-only
//! owner-side namei/path implementation.
//!
//! `VfsState` remains the owner of namespace state, but the pathwalk and
//! path-render logic lives here so `owner/mod.rs` does not also carry the
//! full namei engine.

use trona_kernel::core_types::TronaMsg;
use trona_kernel::ipc;
use trona_protocol::posix::server::POSIX_TTYSRV_PTY_LOOKUP;
use uapi::TRONA_NOT_FOUND;

use crate::owner::pending_ops::{self, PendingOpId};
use crate::server::types::{ClientHandle, PERS_POSIX, PERS_WIN32};
use crate::vfs_core::identity::{FsInstanceId, VnodeKey};
use crate::vfs_core::mount::{MNT_POSIX_ONLY, MNT_WIN32_ONLY};
use crate::vfs_core::vnode::{VT_LNK, VnodeHandle};
use crate::vfs_core::vops::{self, VfsOpResult, VfsResult};

use super::{BOOTSTRAP_PATH_DEPTH_MAX, BOOTSTRAP_PATH_MAX, BOOTSTRAP_SYMLINK_DEPTH_MAX, VfsState};

/// Resumable namei state stashed in `pending_ops::payload_ref` so the
/// owner can re-enter `lookup_path_dynamic_inner` after a deferred
/// backend reply arrives. `#[repr(C)]` because `payload_bytes_mut`
/// returns raw bytes.
#[repr(C)]
pub(crate) struct NameiResumeState {
    pub(crate) path: [u8; BOOTSTRAP_PATH_MAX],
    pub(crate) path_len: u16,
    pub(crate) pos: u16,
    pub(crate) depth: u8,
    pub(crate) follow_final_symlink: u8,
    pub(crate) ignore_case: u8,
    pub(crate) skip_posix_only: u8,
    pub(crate) skip_win32_only: u8,
    pub(crate) resume_step: u8,
    pub(crate) aux_kind: u8,
    pub(crate) _pad: [u8; 5],
    pub(crate) current_packed: u64,
    pub(crate) aux: NameiResumeAux,
}

/// Auxiliary union carried in a deferred op's typed payload alongside
/// the namei walk state. `aux_kind` discriminates the active variant.
/// Variants split into two families:
/// 1. namei sub-step state (`NAMEI_AUX_NONE`, `NAMEI_AUX_PTS`) — set
///    while the walk is in progress and the backend has yielded
///    inside `vops::lookup_child` / `ensure_symlink_target` /
///    `ensure_pts_slave_vnode`.
/// 2. syscall continuation body (`NAMEI_AUX_OPEN`, `STAT`, `ACCESS`,
///    …) — set after `NAMEI_STEP_DONE`, when the walk has resolved a
///    vnode and the syscall handler's tail-work needs to run on the
///    owner thread once a backend RPC completes.
///
/// Readers must check `aux_kind` before access; `_pad` keeps the
/// containing `NameiResumeState` within `PAYLOAD_BUF_BYTES`.
#[repr(C)]
pub(crate) union NameiResumeAux {
    pub(crate) none: NameiAuxNone,
    pub(crate) pts: NameiAuxPts,
    pub(crate) open: OpenContBody,
    pub(crate) stat: StatContBody,
    pub(crate) access: AccessContBody,
    pub(crate) chmod: ChmodContBody,
    pub(crate) chown: ChownContBody,
    pub(crate) utimes: UtimesContBody,
    pub(crate) truncate: TruncateContBody,
    pub(crate) readlink: ReadlinkContBody,
    pub(crate) unlink: UnlinkContBody,
    pub(crate) mkdir: MkdirContBody,
    pub(crate) rename: RenameContBody,
    pub(crate) symlink: SymlinkContBody,
    pub(crate) link: LinkContBody,
    pub(crate) mknod: MknodContBody,
    pub(crate) chdir: ChdirContBody,
    pub(crate) statvfs: StatvfsContBody,
    pub(crate) mount: MountContBody,
    pub(crate) umount: UmountContBody,
    pub(crate) generic: [u8; 96],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct NameiAuxNone {
    pub(crate) _reserved: [u8; 96],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct NameiAuxPts {
    pub(crate) pty_id: u32,
    pub(crate) generation: u32,
    pub(crate) pts_dir_packed: u64,
    pub(crate) _reserved: [u8; 80],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct OpenContBody {
    pub(crate) flags: u32,
    pub(crate) mode: u32,
    pub(crate) dirfd_packed: u64,
    pub(crate) result_fd_hint: i32,
    pub(crate) force_directory: u8,
    pub(crate) stage: u8,
    pub(crate) leaf_offset: u16,
    pub(crate) _pad: [u8; 72],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct StatContBody {
    pub(crate) follow_symlink: u8,
    pub(crate) for_exec: u8,
    pub(crate) _pad0: [u8; 6],
    pub(crate) dirfd_packed: u64,
    pub(crate) _reserved: [u8; 80],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct AccessContBody {
    pub(crate) mode: u32,
    pub(crate) flags: u32,
    pub(crate) dirfd_packed: u64,
    pub(crate) _reserved: [u8; 80],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ChmodContBody {
    pub(crate) mode: u32,
    pub(crate) _pad: [u8; 92],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ChownContBody {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) _pad: [u8; 88],
}

/// `utimensat` continuation body. Each timespec is encoded into a
/// `*_opt` selector (`UTIMENS_OPT_NORMAL = 0` / `UTIMENS_OPT_NOW = 1`
/// / `UTIMENS_OPT_OMIT = 2`) plus a `*_ns` value (nanoseconds since
/// epoch when `_opt == NORMAL`, ignored otherwise). `dirfd_packed`
/// carries the `AT_FDCWD` / fd encoding from `normalize_path_at_owned`,
/// and `flags` carries the syscall's `at_flags` (`AT_SYMLINK_NOFOLLOW`
/// is the only valid bit).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct UtimesContBody {
    pub(crate) atime_opt: u8,
    pub(crate) mtime_opt: u8,
    pub(crate) _pad0: [u8; 6],
    pub(crate) atime_ns: u64,
    pub(crate) mtime_ns: u64,
    pub(crate) dirfd_packed: u64,
    pub(crate) flags: u32,
    pub(crate) _pad1: [u8; 4],
    pub(crate) _reserved: [u8; 56],
}

pub(crate) const UTIMENS_OPT_NORMAL: u8 = 0;
pub(crate) const UTIMENS_OPT_NOW: u8 = 1;
pub(crate) const UTIMENS_OPT_OMIT: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct TruncateContBody {
    pub(crate) length: u64,
    pub(crate) _pad: [u8; 88],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ReadlinkContBody {
    pub(crate) _reserved: [u8; 96],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct UnlinkContBody {
    pub(crate) flags: u32,
    pub(crate) _pad: [u8; 92],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MkdirContBody {
    pub(crate) mode: u32,
    pub(crate) _pad: [u8; 92],
}

/// `rename` / `renameat` continuation. The OLD path lives in
/// `saved.path` (full BOOTSTRAP_PATH_MAX). The NEW path packs inline
/// into the body — limited to `RENAME_NEW_PATH_MAX = 88` bytes.
/// Callers that exceed the new-path limit must reply
/// `TRONA_NAME_TOO_LONG` synchronously before adopting the op.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RenameContBody {
    pub(crate) new_path_len: u8,
    pub(crate) _pad: [u8; 7],
    pub(crate) new_path: [u8; 88],
}

pub(crate) const RENAME_NEW_PATH_MAX: usize = 88;

/// `symlinkat` continuation. The link's path lives in `saved.path`;
/// the symlink target packs inline (up to `SYMLINK_TARGET_INLINE_MAX
/// = 64` bytes — covers virtually all practical relative-path
/// targets and the common `..`-walked absolute targets in /etc / /proc).
/// Targets longer than 64 bytes must reply `TRONA_NAME_TOO_LONG`
/// synchronously before adopting the op.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SymlinkContBody {
    pub(crate) target_len: u8,
    pub(crate) _pad: [u8; 7],
    pub(crate) target: [u8; 64],
    pub(crate) _reserved: [u8; 24],
}

pub(crate) const SYMLINK_TARGET_INLINE_MAX: usize = 64;

/// `linkat` continuation. The SOURCE vnode arrives in
/// `saved.current_packed` after the namei walk on the source path.
/// The DEST path packs inline (`LINK_NEW_PATH_MAX = 88` bytes,
/// same caveat as `RenameContBody`).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct LinkContBody {
    pub(crate) new_path_len: u8,
    pub(crate) _pad: [u8; 7],
    pub(crate) new_path: [u8; 88],
}

pub(crate) const LINK_NEW_PATH_MAX: usize = 88;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MknodContBody {
    pub(crate) mode: u32,
    pub(crate) _pad0: [u8; 4],
    pub(crate) dev: u64,
    pub(crate) _pad: [u8; 80],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ChdirContBody {
    pub(crate) explicit_drive: i8,
    pub(crate) _pad0: [u8; 7],
    pub(crate) _reserved: [u8; 88],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct StatvfsContBody {
    pub(crate) _reserved: [u8; 96],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MountContBody {
    pub(crate) _reserved: [u8; 96],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct UmountContBody {
    pub(crate) flags: u32,
    pub(crate) _pad: [u8; 92],
}

pub(crate) const NAMEI_AUX_NONE: u8 = 0;
pub(crate) const NAMEI_AUX_PTS: u8 = 1;
pub(crate) const NAMEI_AUX_OPEN: u8 = 2;
pub(crate) const NAMEI_AUX_STAT: u8 = 3;
pub(crate) const NAMEI_AUX_ACCESS: u8 = 4;
pub(crate) const NAMEI_AUX_CHMOD: u8 = 5;
pub(crate) const NAMEI_AUX_CHOWN: u8 = 6;
pub(crate) const NAMEI_AUX_UTIMES: u8 = 7;
pub(crate) const NAMEI_AUX_TRUNCATE: u8 = 8;
pub(crate) const NAMEI_AUX_READLINK: u8 = 9;
pub(crate) const NAMEI_AUX_UNLINK: u8 = 10;
pub(crate) const NAMEI_AUX_MKDIR: u8 = 11;
pub(crate) const NAMEI_AUX_RENAME: u8 = 12;
pub(crate) const NAMEI_AUX_SYMLINK: u8 = 13;
pub(crate) const NAMEI_AUX_LINK: u8 = 14;
pub(crate) const NAMEI_AUX_MKNOD: u8 = 15;
pub(crate) const NAMEI_AUX_CHDIR: u8 = 16;
pub(crate) const NAMEI_AUX_STATVFS: u8 = 17;
pub(crate) const NAMEI_AUX_MOUNT: u8 = 18;
pub(crate) const NAMEI_AUX_UMOUNT: u8 = 19;

/// `OpenContBody.stage` values for the open / openat / creat / opendir
/// continuation. The handler stamps the stage when adopting a deferred
/// op so `complete_open_continuation` can pick up the correct sync
/// tail after each backend reply.
pub(crate) const OPEN_STAGE_LOOKUP: u8 = 0;
pub(crate) const OPEN_STAGE_PARENT_LOOKUP: u8 = 1;
pub(crate) const OPEN_STAGE_CREATE: u8 = 2;
pub(crate) const OPEN_STAGE_TRUNCATE: u8 = 3;

#[inline]
pub(crate) const fn namei_aux_none() -> NameiResumeAux {
    NameiResumeAux {
        none: NameiAuxNone { _reserved: [0; 96] },
    }
}

#[inline]
pub(crate) const fn namei_aux_open(body: OpenContBody) -> NameiResumeAux {
    NameiResumeAux { open: body }
}

#[inline]
pub(crate) const fn namei_aux_stat(body: StatContBody) -> NameiResumeAux {
    NameiResumeAux { stat: body }
}

#[inline]
pub(crate) const fn namei_aux_access(body: AccessContBody) -> NameiResumeAux {
    NameiResumeAux { access: body }
}

#[inline]
pub(crate) const fn namei_aux_chmod(body: ChmodContBody) -> NameiResumeAux {
    NameiResumeAux { chmod: body }
}

#[inline]
pub(crate) const fn namei_aux_chown(body: ChownContBody) -> NameiResumeAux {
    NameiResumeAux { chown: body }
}

#[inline]
pub(crate) const fn namei_aux_utimes(body: UtimesContBody) -> NameiResumeAux {
    NameiResumeAux { utimes: body }
}

#[inline]
pub(crate) const fn namei_aux_truncate(body: TruncateContBody) -> NameiResumeAux {
    NameiResumeAux { truncate: body }
}

#[inline]
pub(crate) const fn namei_aux_readlink(body: ReadlinkContBody) -> NameiResumeAux {
    NameiResumeAux { readlink: body }
}

#[inline]
pub(crate) const fn namei_aux_unlink(body: UnlinkContBody) -> NameiResumeAux {
    NameiResumeAux { unlink: body }
}

#[inline]
pub(crate) const fn namei_aux_mkdir(body: MkdirContBody) -> NameiResumeAux {
    NameiResumeAux { mkdir: body }
}

#[inline]
pub(crate) const fn namei_aux_rename(body: RenameContBody) -> NameiResumeAux {
    NameiResumeAux { rename: body }
}

#[inline]
pub(crate) const fn namei_aux_symlink(body: SymlinkContBody) -> NameiResumeAux {
    NameiResumeAux { symlink: body }
}

#[inline]
pub(crate) const fn namei_aux_link(body: LinkContBody) -> NameiResumeAux {
    NameiResumeAux { link: body }
}

#[inline]
pub(crate) const fn namei_aux_mknod(body: MknodContBody) -> NameiResumeAux {
    NameiResumeAux { mknod: body }
}

#[inline]
pub(crate) const fn namei_aux_chdir(body: ChdirContBody) -> NameiResumeAux {
    NameiResumeAux { chdir: body }
}

#[inline]
pub(crate) const fn namei_aux_statvfs(body: StatvfsContBody) -> NameiResumeAux {
    NameiResumeAux { statvfs: body }
}

#[inline]
pub(crate) const fn namei_aux_mount(body: MountContBody) -> NameiResumeAux {
    NameiResumeAux { mount: body }
}

#[inline]
pub(crate) const fn namei_aux_umount(body: UmountContBody) -> NameiResumeAux {
    NameiResumeAux { umount: body }
}

const _NAMEI_RESUME_FITS_PAYLOAD: () = assert!(
    core::mem::size_of::<NameiResumeState>() <= crate::owner::pending_ops::PAYLOAD_BUF_BYTES
);

/// Each `NameiResumeAux` variant must be exactly 96 bytes so the
/// union's size matches `generic: [u8; 96]` and a body added or
/// resized in one variant cannot silently grow the others.
const _NAMEI_AUX_VARIANTS_ARE_96: () = {
    assert!(core::mem::size_of::<NameiAuxNone>() == 96);
    assert!(core::mem::size_of::<NameiAuxPts>() == 96);
    assert!(core::mem::size_of::<OpenContBody>() == 96);
    assert!(core::mem::size_of::<StatContBody>() == 96);
    assert!(core::mem::size_of::<AccessContBody>() == 96);
    assert!(core::mem::size_of::<ChmodContBody>() == 96);
    assert!(core::mem::size_of::<ChownContBody>() == 96);
    assert!(core::mem::size_of::<UtimesContBody>() == 96);
    assert!(core::mem::size_of::<TruncateContBody>() == 96);
    assert!(core::mem::size_of::<ReadlinkContBody>() == 96);
    assert!(core::mem::size_of::<UnlinkContBody>() == 96);
    assert!(core::mem::size_of::<MkdirContBody>() == 96);
    assert!(core::mem::size_of::<RenameContBody>() == 96);
    assert!(core::mem::size_of::<SymlinkContBody>() == 96);
    assert!(core::mem::size_of::<LinkContBody>() == 96);
    assert!(core::mem::size_of::<MknodContBody>() == 96);
    assert!(core::mem::size_of::<ChdirContBody>() == 96);
    assert!(core::mem::size_of::<StatvfsContBody>() == 96);
    assert!(core::mem::size_of::<MountContBody>() == 96);
    assert!(core::mem::size_of::<UmountContBody>() == 96);
    assert!(core::mem::size_of::<NameiResumeAux>() == 96);
};

pub(crate) const NAMEI_STEP_AFTER_LOOKUP_CHILD: u8 = 1;
pub(crate) const NAMEI_STEP_AFTER_ENSURE_SYMLINK: u8 = 2;
/// Namei walk has resolved to a vnode. The syscall continuation phase
/// dispatches by `PendingOp.kind` (PO_KIND_*_CONT) to the matching
/// `complete_*_continuation` handler.
pub(crate) const NAMEI_STEP_DONE: u8 = 3;
/// `POSIX_TTYSRV_PTY_LOOKUP` reply has arrived. `lookup_path_dynamic_resume`
/// extracts the generation from `completion.backend_reply.regs[0]` and
/// chains into `ensure_pts_slave_vnode_with_generation` to produce the
/// resolved vnode.
pub(crate) const NAMEI_STEP_AFTER_PTS_LOOKUP: u8 = 4;

unsafe fn save_namei_resume_state(
    op_id: PendingOpId,
    current: VnodeHandle,
    path: &[u8],
    pos: usize,
    depth: u8,
    follow_final_symlink: bool,
    ignore_case: bool,
    skip_posix_only: bool,
    skip_win32_only: bool,
    resume_step: u8,
    aux_kind: u8,
    aux: NameiResumeAux,
) -> bool {
    unsafe {
        // Reuse the existing payload if a backend vop already
        // allocated one before returning `Deferred(op_id)`. Allocating
        // a fresh payload here without reuse would leak the placeholder
        // and corrupt the continuation framework's payload accounting.
        let existing = pending_ops::get(op_id)
            .map(|op| op.payload_ref)
            .unwrap_or(0);
        let (payload_ref, allocated) = if pending_ops::payload_bytes(existing).is_some() {
            (existing, false)
        } else {
            let Some(p) = pending_ops::alloc_payload() else {
                return false;
            };
            (p, true)
        };
        let Some(buf) = pending_ops::payload_bytes_mut(payload_ref) else {
            if allocated {
                pending_ops::release_payload(payload_ref);
            }
            return false;
        };
        let Some(op) = pending_ops::get_mut(op_id) else {
            if allocated {
                pending_ops::release_payload(payload_ref);
            }
            return false;
        };
        let state_ptr = buf.as_mut_ptr() as *mut NameiResumeState;
        (*state_ptr) = NameiResumeState {
            path: [0; BOOTSTRAP_PATH_MAX],
            path_len: core::cmp::min(path.len(), BOOTSTRAP_PATH_MAX) as u16,
            pos: pos as u16,
            depth,
            follow_final_symlink: follow_final_symlink as u8,
            ignore_case: ignore_case as u8,
            skip_posix_only: skip_posix_only as u8,
            skip_win32_only: skip_win32_only as u8,
            resume_step,
            aux_kind,
            _pad: [0; 5],
            current_packed: ((current.epoch() as u64) << 32) | (current.slot() as u64),
            aux,
        };
        let copy_len = core::cmp::min(path.len(), BOOTSTRAP_PATH_MAX);
        (&mut (*state_ptr).path)[..copy_len].copy_from_slice(&path[..copy_len]);
        op.payload_ref = payload_ref;
        true
    }
}

pub(super) fn bootstrap_build_absolute_path(
    state: &VfsState,
    vnode: VnodeHandle,
    out: &mut [u8; BOOTSTRAP_PATH_MAX],
) -> Option<usize> {
    let root = state.root_vnode()?;
    if vnode == root {
        out[0] = b'/';
        return Some(1);
    }

    let mut chain = [usize::MAX; BOOTSTRAP_PATH_DEPTH_MAX];
    let mut depth = 0usize;
    let mut current = vnode;
    while current.is_valid() && current != root {
        let mut found = None;
        let limit = state.bootstrap.entry_count as usize;
        for idx in 0..limit {
            let entry = &state.bootstrap.entries[idx];
            if entry.active != 0 && entry.vnode == current {
                found = Some(idx);
                current = entry.parent;
                break;
            }
        }
        let idx = found?;
        if depth >= chain.len() {
            return None;
        }
        chain[depth] = idx;
        depth += 1;
    }
    if current != root {
        return None;
    }

    let mut len = 1usize;
    out[0] = b'/';
    while depth > 0 {
        depth -= 1;
        let entry = &state.bootstrap.entries[chain[depth]];
        let name_len = entry.name_len as usize;
        if len > 1 {
            if len >= out.len() {
                return None;
            }
            out[len] = b'/';
            len += 1;
        }
        if len + name_len > out.len() {
            return None;
        }
        out[len..len + name_len].copy_from_slice(&entry.name[..name_len]);
        len += name_len;
    }
    Some(len)
}

pub(super) fn bootstrap_path_for_vnode(
    state: &VfsState,
    vnode: VnodeHandle,
    out: &mut [u8],
) -> Option<usize> {
    let mut tmp = [0u8; BOOTSTRAP_PATH_MAX];
    let len = if let Some(len) = bootstrap_build_absolute_path(state, vnode, &mut tmp) {
        len
    } else {
        let mut covered = None;
        let mut mount_path_len = 0usize;
        state.mounts.for_each_active(|_, mount| {
            if mount.root_vnode == vnode {
                if mount.covered.handle.is_valid() {
                    covered = Some(mount.covered.handle);
                } else if mount.covered.id != VnodeKey::INVALID {
                    covered = state.vnode_by_key(mount.covered.id);
                } else if mount.mount_path_len != 0 {
                    let len = mount.mount_path_len as usize;
                    if len <= tmp.len() {
                        tmp[..len].copy_from_slice(&mount.mount_path[..len]);
                        mount_path_len = len;
                    }
                }
                return false;
            }
            true
        });
        if let Some(covered) = covered {
            bootstrap_build_absolute_path(state, covered, &mut tmp)?
        } else if mount_path_len != 0 {
            mount_path_len
        } else {
            vops::build_path_for_vnode(state, vnode, &mut tmp)?
        }
    };
    if len > out.len() {
        return None;
    }
    out[..len].copy_from_slice(&tmp[..len]);
    Some(len)
}

pub(super) fn render_anchor_path(
    state: &VfsState,
    anchor: crate::vfs_core::namei::PathAnchor,
    out: &mut [u8],
) -> Option<usize> {
    let vnode = state.resolve_anchor_vnode(anchor)?;
    bootstrap_path_for_vnode(state, vnode, out)
}

/// Helper: convert `VfsResult<Option<VnodeHandle>>` into the legacy
/// `Option<VnodeHandle>` shape callers still expect, while writing
/// `reply.label` to `REPLY_DEFERRED_LABEL` on `Deferred` and to the
/// real error code on `Err`. Returns `None` after writing the label
/// when the caller should bail out of dispatch; returns `Some(vh)` on
/// successful lookup.
pub(crate) unsafe fn unwrap_lookup_or_set_label(
    r: VfsResult<Option<VnodeHandle>>,
    reply: *mut TronaMsg,
) -> Option<VnodeHandle> {
    unsafe {
        match r {
            Ok(VfsOpResult::Complete(Some(vh))) => Some(vh),
            Ok(VfsOpResult::Complete(None)) => {
                (*reply).label = TRONA_NOT_FOUND;
                None
            }
            Ok(VfsOpResult::Deferred(_)) => {
                (*reply).label = crate::fileops::tty_wait::REPLY_DEFERRED_LABEL;
                None
            }
            Err(err) => {
                (*reply).label = err;
                None
            }
        }
    }
}

pub(super) fn bootstrap_lookup_parent_and_name<'a>(
    state: &VfsState,
    path: &'a [u8],
) -> Option<(VnodeHandle, &'a [u8])> {
    if path.len() <= 1 || path[0] != b'/' {
        return None;
    }

    let mut leaf_start = path.len();
    while leaf_start > 0 && path[leaf_start - 1] != b'/' {
        leaf_start -= 1;
    }
    if leaf_start >= path.len() {
        return None;
    }

    let name = &path[leaf_start..];
    if name.is_empty() || name.contains(&b'/') {
        return None;
    }

    let parent = if leaf_start == 1 {
        state.root_vnode()?
    } else {
        state.bootstrap_lookup_path(&path[..leaf_start - 1])?
    };
    Some((parent, name))
}

pub(super) fn bootstrap_lookup_parent_and_name_for_personality<'a>(
    state: &VfsState,
    path: &'a [u8],
    personality: u8,
) -> Option<(VnodeHandle, &'a [u8])> {
    if path.len() <= 1 || path[0] != b'/' {
        return None;
    }

    let mut leaf_start = path.len();
    while leaf_start > 0 && path[leaf_start - 1] != b'/' {
        leaf_start -= 1;
    }
    if leaf_start >= path.len() {
        return None;
    }

    let name = &path[leaf_start..];
    if name.is_empty() || name.contains(&b'/') {
        return None;
    }

    let parent = if leaf_start == 1 {
        state.root_vnode()?
    } else {
        state.bootstrap_lookup_path_for_personality(&path[..leaf_start - 1], false, personality)?
    };
    Some((parent, name))
}

pub(super) fn lookup_result_for_vnode(
    state: &VfsState,
    vnode: VnodeHandle,
) -> Option<crate::vfs_core::namei::LookupResult> {
    Some(crate::vfs_core::namei::LookupResult {
        anchor: state.anchor_for_vnode(vnode)?,
        handle: vnode,
    })
}

/// Sync wrapper: collapses any deferred-mid-walk result to `None`,
/// so the caller cannot distinguish "not found" from "backend
/// yielded". Suitable only for legacy paths whose syscall handlers
/// have not yet been ported to the syscall continuation framework —
/// new handlers must use [`lookup_parent_for_client_deferred`] to
/// preserve the deferred op_id and resume after the backend reply.
pub(super) fn lookup_parent_for_client(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    abs_path: &[u8],
) -> Option<crate::vfs_core::namei::ParentLookup> {
    if abs_path.is_empty() || abs_path[0] != b'/' {
        return None;
    }
    let mut leaf_start = abs_path.len();
    while leaf_start > 0 && abs_path[leaf_start - 1] != b'/' {
        leaf_start -= 1;
    }
    if leaf_start >= abs_path.len() {
        return None;
    }
    let parent_vh = if leaf_start <= 1 {
        state.root_vnode()?
    } else {
        match lookup_path_dynamic_for_client(state, cli_handle, &abs_path[..leaf_start - 1], false)
        {
            Ok(VfsOpResult::Complete(Some(vh))) => vh,
            _ => return None,
        }
    };
    Some(crate::vfs_core::namei::ParentLookup {
        parent: lookup_result_for_vnode(state, parent_vh)?,
        leaf_offset: leaf_start,
    })
}

/// Deferred-aware variant of [`lookup_parent_for_client`]. Propagates
/// `VfsOpResult::Deferred(op_id)` so syscall continuation handlers can
/// stash their tail-state on the same op and resume once the backend
/// reply lands.
pub(super) fn lookup_parent_for_client_deferred(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    abs_path: &[u8],
) -> VfsResult<Option<crate::vfs_core::namei::ParentLookup>> {
    if abs_path.is_empty() || abs_path[0] != b'/' {
        return Ok(VfsOpResult::Complete(None));
    }
    let mut leaf_start = abs_path.len();
    while leaf_start > 0 && abs_path[leaf_start - 1] != b'/' {
        leaf_start -= 1;
    }
    if leaf_start >= abs_path.len() {
        return Ok(VfsOpResult::Complete(None));
    }
    let parent_vh = if leaf_start <= 1 {
        match state.root_vnode() {
            Some(vh) => vh,
            None => return Ok(VfsOpResult::Complete(None)),
        }
    } else {
        match lookup_path_dynamic_for_client(state, cli_handle, &abs_path[..leaf_start - 1], false)?
        {
            VfsOpResult::Complete(Some(vh)) => vh,
            VfsOpResult::Complete(None) => return Ok(VfsOpResult::Complete(None)),
            VfsOpResult::Deferred(op_id) => return Ok(VfsOpResult::Deferred(op_id)),
        }
    };
    let parent = match lookup_result_for_vnode(state, parent_vh) {
        Some(p) => p,
        None => return Ok(VfsOpResult::Complete(None)),
    };
    Ok(VfsOpResult::Complete(Some(
        crate::vfs_core::namei::ParentLookup {
            parent,
            leaf_offset: leaf_start,
        },
    )))
}

pub(super) fn compose_dynamic_symlink_path(
    state: &VfsState,
    full_path: &[u8],
    component_start: usize,
    target: &[u8],
    tail: &[u8],
    out: &mut [u8; BOOTSTRAP_PATH_MAX],
) -> Option<usize> {
    let mut raw = [0u8; BOOTSTRAP_PATH_MAX];
    let mut raw_len = 0usize;

    if target.first().copied() != Some(b'/') {
        let prefix_len = if component_start > 1 {
            component_start - 1
        } else {
            1
        };
        if prefix_len > raw.len() {
            return None;
        }
        raw[..prefix_len].copy_from_slice(&full_path[..prefix_len]);
        raw_len = prefix_len;
        if raw_len > 1 && raw[raw_len - 1] != b'/' {
            if raw_len >= raw.len() {
                return None;
            }
            raw[raw_len] = b'/';
            raw_len += 1;
        }
    }

    if raw_len + target.len() > raw.len() {
        return None;
    }
    raw[raw_len..raw_len + target.len()].copy_from_slice(target);
    raw_len += target.len();

    if !tail.is_empty() {
        if raw_len > 1 && raw[raw_len - 1] != b'/' {
            if raw_len >= raw.len() {
                return None;
            }
            raw[raw_len] = b'/';
            raw_len += 1;
        }
        if raw_len + tail.len() > raw.len() {
            return None;
        }
        raw[raw_len..raw_len + tail.len()].copy_from_slice(tail);
        raw_len += tail.len();
    }

    state.normalize_bootstrap_absolute_path(&raw[..raw_len], out)
}

pub(super) fn bootstrap_compose_symlink_path(
    state: &VfsState,
    link_vh: VnodeHandle,
    target: &[u8],
    tail: &[u8],
    out: &mut [u8; BOOTSTRAP_PATH_MAX],
) -> Option<usize> {
    let mut raw = [0u8; BOOTSTRAP_PATH_MAX];
    let mut raw_len = 0usize;

    if target.first().copied() != Some(b'/') {
        let parent = state.bootstrap_parent_dir(link_vh);
        raw_len = bootstrap_build_absolute_path(state, parent, &mut raw)?;
        if raw_len > 1 {
            if raw_len >= raw.len() {
                return None;
            }
            raw[raw_len] = b'/';
            raw_len += 1;
        }
    }

    if raw_len + target.len() > raw.len() {
        return None;
    }
    raw[raw_len..raw_len + target.len()].copy_from_slice(target);
    raw_len += target.len();

    if !tail.is_empty() {
        if raw_len > 1 && raw[raw_len - 1] != b'/' {
            if raw_len >= raw.len() {
                return None;
            }
            raw[raw_len] = b'/';
            raw_len += 1;
        }
        if raw_len + tail.len() > raw.len() {
            return None;
        }
        raw[raw_len..raw_len + tail.len()].copy_from_slice(tail);
        raw_len += tail.len();
    }

    state.normalize_bootstrap_absolute_path(&raw[..raw_len], out)
}

pub(super) fn bootstrap_lookup_path_inner(
    state: &VfsState,
    path: &[u8],
    depth: u8,
    follow_final_symlink: bool,
    ignore_case: bool,
    skip_posix_only: bool,
    skip_win32_only: bool,
) -> Option<VnodeHandle> {
    if depth > BOOTSTRAP_SYMLINK_DEPTH_MAX {
        return None;
    }

    let mut current = state.root_vnode()?;
    if path.is_empty() || path == b"/" {
        return Some(current);
    }

    let mut pos = 0usize;
    while pos < path.len() && path[pos] == b'/' {
        pos += 1;
    }

    while pos < path.len() {
        let start = pos;
        while pos < path.len() && path[pos] != b'/' {
            pos += 1;
        }
        let component = &path[start..pos];
        while pos < path.len() && path[pos] == b'/' {
            pos += 1;
        }
        if component.is_empty() {
            continue;
        }
        current = state.bootstrap_lookup_child_with_case(current, component, ignore_case)?;
        let mut vnode = state.vnodes.get(current)?;
        if vnode.covered_by.id != FsInstanceId::INVALID {
            let child_mount = if vnode.covered_by.handle.is_valid() {
                Some(vnode.covered_by.handle)
            } else {
                state.mount_by_fs_instance_id(vnode.covered_by.id)
            }?;
            let mount = state.mounts.get(child_mount)?;
            if (skip_posix_only && (mount.flags & MNT_POSIX_ONLY) != 0)
                || (skip_win32_only && (mount.flags & MNT_WIN32_ONLY) != 0)
            {
            } else {
                current = mount.root_vnode;
                vnode = state.vnodes.get(current)?;
            }
        }
        if vnode.vtype == VT_LNK {
            let final_component = pos >= path.len();
            if final_component && !follow_final_symlink {
                return Some(current);
            }
            let target = unsafe {
                core::slice::from_raw_parts(vnode.data as *const u8, vnode.size as usize)
            };
            let mut composed = [0u8; BOOTSTRAP_PATH_MAX];
            let composed_len = bootstrap_compose_symlink_path(
                state,
                current,
                target,
                &path[pos..],
                &mut composed,
            )?;
            return bootstrap_lookup_path_inner(
                state,
                &composed[..composed_len],
                depth + 1,
                follow_final_symlink,
                ignore_case,
                skip_posix_only,
                skip_win32_only,
            );
        }
    }

    Some(current)
}

pub(super) fn lookup_path_dynamic_inner(
    state: &mut VfsState,
    path: &[u8],
    depth: u8,
    follow_final_symlink: bool,
    ignore_case: bool,
    skip_posix_only: bool,
    skip_win32_only: bool,
) -> VfsResult<Option<VnodeHandle>> {
    if depth > BOOTSTRAP_SYMLINK_DEPTH_MAX {
        return Ok(VfsOpResult::Complete(None));
    }
    let Some(current) = state.root_vnode() else {
        return Ok(VfsOpResult::Complete(None));
    };
    if path.is_empty() || path == b"/" {
        return Ok(VfsOpResult::Complete(Some(current)));
    }
    let mut pos = 0usize;
    while pos < path.len() && path[pos] == b'/' {
        pos += 1;
    }
    lookup_path_dynamic_walk(
        state,
        path,
        pos,
        current,
        depth,
        follow_final_symlink,
        ignore_case,
        skip_posix_only,
        skip_win32_only,
    )
}

fn lookup_path_dynamic_walk(
    state: &mut VfsState,
    path: &[u8],
    mut pos: usize,
    mut current: VnodeHandle,
    depth: u8,
    follow_final_symlink: bool,
    ignore_case: bool,
    skip_posix_only: bool,
    skip_win32_only: bool,
) -> VfsResult<Option<VnodeHandle>> {
    while pos < path.len() {
        let start = pos;
        let parent = current;
        while pos < path.len() && path[pos] != b'/' {
            pos += 1;
        }
        let component = &path[start..pos];
        while pos < path.len() && path[pos] == b'/' {
            pos += 1;
        }
        if component.is_empty() {
            continue;
        }

        current = if let Some(child) =
            state.bootstrap_lookup_child_with_case(parent, component, ignore_case)
        {
            child
        } else {
            match vops::lookup_child(state, parent, component)? {
                VfsOpResult::Complete(Some(vh)) => vh,
                VfsOpResult::Complete(None) => return Ok(VfsOpResult::Complete(None)),
                VfsOpResult::Deferred(op_id) => {
                    let saved = unsafe {
                        save_namei_resume_state(
                            op_id,
                            parent,
                            path,
                            start,
                            depth,
                            follow_final_symlink,
                            ignore_case,
                            skip_posix_only,
                            skip_win32_only,
                            NAMEI_STEP_AFTER_LOOKUP_CHILD,
                            NAMEI_AUX_NONE,
                            namei_aux_none(),
                        )
                    };
                    let _ = saved;
                    return Ok(VfsOpResult::Deferred(op_id));
                }
            }
        };

        let mut vnode = match state.vnodes.get(current) {
            Some(vn) => vn,
            None => return Ok(VfsOpResult::Complete(None)),
        };
        if vnode.covered_by.id != FsInstanceId::INVALID {
            let child_mount = if vnode.covered_by.handle.is_valid() {
                Some(vnode.covered_by.handle)
            } else {
                state.mount_by_fs_instance_id(vnode.covered_by.id)
            };
            let Some(child_mount) = child_mount else {
                return Ok(VfsOpResult::Complete(None));
            };
            let Some(mount) = state.mounts.get(child_mount) else {
                return Ok(VfsOpResult::Complete(None));
            };
            if (skip_posix_only && (mount.flags & MNT_POSIX_ONLY) != 0)
                || (skip_win32_only && (mount.flags & MNT_WIN32_ONLY) != 0)
            {
            } else {
                current = mount.root_vnode;
                vnode = match state.vnodes.get(current) {
                    Some(vn) => vn,
                    None => return Ok(VfsOpResult::Complete(None)),
                };
            }
        }

        if vnode.vtype == VT_LNK {
            if vnode.data.is_null() {
                match vops::ensure_symlink_target(state, current)? {
                    VfsOpResult::Complete(true) => {}
                    VfsOpResult::Complete(false) => return Ok(VfsOpResult::Complete(None)),
                    VfsOpResult::Deferred(op_id) => {
                        let saved = unsafe {
                            save_namei_resume_state(
                                op_id,
                                parent,
                                path,
                                start,
                                depth,
                                follow_final_symlink,
                                ignore_case,
                                skip_posix_only,
                                skip_win32_only,
                                NAMEI_STEP_AFTER_ENSURE_SYMLINK,
                                NAMEI_AUX_NONE,
                                namei_aux_none(),
                            )
                        };
                        let _ = saved;
                        return Ok(VfsOpResult::Deferred(op_id));
                    }
                }
                vnode = match state.vnodes.get(current) {
                    Some(vn) => vn,
                    None => return Ok(VfsOpResult::Complete(None)),
                };
            }
            let final_component = pos >= path.len();
            if final_component && !follow_final_symlink {
                return Ok(VfsOpResult::Complete(Some(current)));
            }
            if vnode.data.is_null() {
                return Ok(VfsOpResult::Complete(None));
            }
            let target = unsafe {
                core::slice::from_raw_parts(vnode.data as *const u8, vnode.size as usize)
            };
            let mut composed = [0u8; BOOTSTRAP_PATH_MAX];
            let Some(composed_len) = compose_dynamic_symlink_path(
                state,
                path,
                start,
                target,
                &path[pos..],
                &mut composed,
            ) else {
                return Ok(VfsOpResult::Complete(None));
            };
            return lookup_path_dynamic_inner(
                state,
                &composed[..composed_len],
                depth + 1,
                follow_final_symlink,
                ignore_case,
                skip_posix_only,
                skip_win32_only,
            );
        }
    }

    Ok(VfsOpResult::Complete(Some(current)))
}

unsafe fn lookup_path_dynamic_resume(
    state: &mut VfsState,
    saved: &NameiResumeState,
    completion: &super::backend_rpc::PendingBackendCompletion,
) -> VfsResult<Option<VnodeHandle>> {
    if saved.resume_step == NAMEI_STEP_AFTER_PTS_LOOKUP {
        if completion.backend_err != 0 || completion.backend_reply.label != uapi::TRONA_OK {
            return Ok(VfsOpResult::Complete(None));
        }
        let generation = completion.backend_reply.regs[0] as u32;
        let pty_id = completion.ctx.data[0] as u32;
        return Ok(VfsOpResult::Complete(
            ensure_pts_slave_vnode_with_generation(state, pty_id, generation),
        ));
    }
    if saved.resume_step == NAMEI_STEP_AFTER_LOOKUP_CHILD {
        // The per-vop completion handler (`complete_saltyfs_lookup_child`)
        // already advanced `saved.current_packed` / `saved.pos` past the
        // resolved component on success. NOT_FOUND / error left the
        // saved state untouched so we can decide here without
        // re-driving the walk into the same `lookup_child` enqueue loop.
        if completion.backend_err != 0 {
            return Err(uapi::TRONA_IO_ERROR);
        }
        match completion.backend_reply.label {
            uapi::TRONA_OK => {}
            uapi::TRONA_NOT_FOUND => {
                return Ok(VfsOpResult::Complete(None));
            }
            err => return Err(err),
        }
    }
    if saved.resume_step == NAMEI_STEP_AFTER_ENSURE_SYMLINK {
        // `complete_saltyfs_readlink` installed the link-target bytes
        // on success. Errors / NOT_FOUND left the symlink's `data`
        // null, so re-driving the walk would re-enqueue
        // `ensure_symlink_target` forever — short-circuit explicitly.
        if completion.backend_err != 0 {
            return Err(uapi::TRONA_IO_ERROR);
        }
        match completion.backend_reply.label {
            uapi::TRONA_OK => {}
            uapi::TRONA_NOT_FOUND => {
                return Ok(VfsOpResult::Complete(None));
            }
            err => return Err(err),
        }
    }
    let path_len = (saved.path_len as usize).min(BOOTSTRAP_PATH_MAX);
    let path = &saved.path[..path_len];
    let pos = saved.pos as usize;
    let current = crate::arena::Handle::<crate::vfs_core::vnode::Vnode>::new(
        saved.current_packed as u32,
        (saved.current_packed >> 32) as u32,
    );
    lookup_path_dynamic_walk(
        state,
        path,
        pos,
        current,
        saved.depth,
        saved.follow_final_symlink != 0,
        saved.ignore_case != 0,
        saved.skip_posix_only != 0,
        saved.skip_win32_only != 0,
    )
}

/// Owner-side completion handler for namei resume. Called from
/// `complete_backend_op` cascade. Consumes the completion when the
/// op's `kind` is `PO_KIND_NAMEI_RESUME` (namei-only resume) or any
/// `PO_KIND_*_CONT` (syscall continuation whose namei phase yielded).
/// Behaviour:
/// - If `saved.resume_step == NAMEI_STEP_DONE` the namei phase already
///   finished; route directly to `dispatch_syscall_continuation`.
/// - Otherwise re-drive the walk. If the walk resolves to a vnode and
///   this op is a syscall continuation, transition to
///   `NAMEI_STEP_DONE` (carrying the vnode in `current_packed`) and
///   dispatch. A pure namei-only op simply releases the saved reply
///   slot — the caller of the original walk owns the final reply.
pub(crate) unsafe fn complete_namei_resume(
    state: &mut VfsState,
    completion: &super::backend_rpc::PendingBackendCompletion,
) -> bool {
    let op_id = pending_ops::PendingOpId::from_raw(completion.op_id);
    let Some(op) = pending_ops::get(op_id) else {
        return false;
    };
    let kind = op.kind;
    let consumes = kind == pending_ops::PO_KIND_NAMEI_RESUME
        || (kind >= pending_ops::PO_KIND_OPEN_CONT
            && kind <= pending_ops::PO_KIND_RESOLVE_PATH_BACKING_CONT);
    if !consumes {
        return false;
    }

    let payload_ref = op.payload_ref;
    let Some(buf) = pending_ops::payload_bytes(payload_ref) else {
        let reply_slot = pending_ops::take_reply_and_free(op_id);
        if reply_slot != 0 {
            crate::fileops::tty_wait::release_reply_slot(reply_slot);
        }
        return true;
    };
    let saved: NameiResumeState = core::ptr::read(buf.as_ptr() as *const NameiResumeState);

    if saved.resume_step == NAMEI_STEP_DONE {
        return dispatch_syscall_continuation(state, op_id, kind, &saved, completion);
    }

    let walk = lookup_path_dynamic_resume(state, &saved, completion);
    match walk {
        Ok(VfsOpResult::Complete(vh_opt)) => {
            if kind == pending_ops::PO_KIND_NAMEI_RESUME {
                let reply_slot = pending_ops::take_reply_and_free(op_id);
                if reply_slot != 0 {
                    crate::fileops::tty_wait::release_reply_slot(reply_slot);
                }
                return true;
            }
            let Some(buf_mut) = pending_ops::payload_bytes_mut(payload_ref) else {
                let reply_slot = pending_ops::take_reply_and_free(op_id);
                if reply_slot != 0 {
                    let mut reply = TronaMsg::zeroed();
                    reply.label = uapi::TRONA_INVALID_OPERATION;
                    crate::fileops::tty_wait::send_saved_reply(reply_slot, &raw const reply);
                }
                return true;
            };
            let state_ptr = buf_mut.as_mut_ptr() as *mut NameiResumeState;
            (*state_ptr).resume_step = NAMEI_STEP_DONE;
            // Pass "not-found" through as Handle::INVALID rather than
            // short-circuiting with NOT_FOUND here. Open with O_CREAT
            // proceeds to create when the namei walk ends with no
            // existing entry; stat / access / readlink want NOT_FOUND.
            // The decision belongs to each `complete_*_continuation`.
            (*state_ptr).current_packed = match vh_opt {
                Some(vh) => ((vh.epoch() as u64) << 32) | (vh.slot() as u64),
                None => u32::MAX as u64,
            };
            let saved_done: NameiResumeState =
                core::ptr::read(buf_mut.as_ptr() as *const NameiResumeState);
            dispatch_syscall_continuation(state, op_id, kind, &saved_done, completion)
        }
        Ok(VfsOpResult::Deferred(new_op_id)) => {
            if !crate::owner::continuation::transition_to_chained_op(op_id, new_op_id) {
                let reply_slot = pending_ops::take_reply_and_free(op_id);
                if reply_slot != 0 {
                    let mut reply = TronaMsg::zeroed();
                    reply.label = uapi::TRONA_INVALID_OPERATION;
                    crate::fileops::tty_wait::send_saved_reply(reply_slot, &raw const reply);
                }
            }
            true
        }
        Err(err) => {
            let reply_slot = pending_ops::take_reply_and_free(op_id);
            if reply_slot != 0 {
                let mut reply = TronaMsg::zeroed();
                reply.label = err;
                crate::fileops::tty_wait::send_saved_reply(reply_slot, &raw const reply);
            }
            true
        }
    }
}

/// Owner-side dispatcher invoked once namei has resolved a vnode for a
/// syscall-continuation `PendingOp`. Routes by `PO_KIND_*_CONT` to the
/// `complete_*_continuation` handler in the relevant `fileops/*.rs`
/// module. Unrecognised kinds fall through to `TRONA_NOT_SUPPORTED` so
/// the framework fails closed.
unsafe fn dispatch_syscall_continuation(
    state: &mut VfsState,
    op_id: PendingOpId,
    kind: pending_ops::PendingOpKind,
    saved: &NameiResumeState,
    completion: &super::backend_rpc::PendingBackendCompletion,
) -> bool {
    unsafe {
        match kind {
            pending_ops::PO_KIND_OPEN_CONT => {
                crate::fileops::open::complete_open_continuation(state, op_id, saved, completion)
            }
            pending_ops::PO_KIND_STAT_CONT => {
                crate::fileops::stat::complete_stat_continuation(state, op_id, saved, completion)
            }
            pending_ops::PO_KIND_ACCESS_CONT => {
                crate::fileops::misc::complete_access_continuation(state, op_id, saved, completion)
            }
            pending_ops::PO_KIND_CHMOD_CONT => {
                crate::fileops::attr::complete_chmod_continuation(state, op_id, saved, completion)
            }
            pending_ops::PO_KIND_CHOWN_CONT => {
                crate::fileops::attr::complete_chown_continuation(state, op_id, saved, completion)
            }
            pending_ops::PO_KIND_UTIMES_CONT => {
                crate::fileops::attr::complete_utimes_continuation(state, op_id, saved, completion)
            }
            pending_ops::PO_KIND_TRUNCATE_CONT => {
                crate::fileops::attr::complete_truncate_continuation(
                    state, op_id, saved, completion,
                )
            }
            pending_ops::PO_KIND_READLINK_CONT => {
                crate::fileops::backing::complete_readlink_continuation(
                    state, op_id, saved, completion,
                )
            }
            pending_ops::PO_KIND_UNLINK_CONT => {
                crate::fileops::mutate::complete_unlink_continuation(
                    state, op_id, saved, completion,
                )
            }
            pending_ops::PO_KIND_MKDIR_CONT => {
                crate::fileops::mutate::complete_mkdir_continuation(state, op_id, saved, completion)
            }
            pending_ops::PO_KIND_RENAME_CONT => {
                crate::fileops::mutate::complete_rename_continuation(
                    state, op_id, saved, completion,
                )
            }
            pending_ops::PO_KIND_SYMLINK_CONT => {
                crate::fileops::mutate::complete_symlink_continuation(
                    state, op_id, saved, completion,
                )
            }
            pending_ops::PO_KIND_LINK_CONT => {
                crate::fileops::mutate::complete_link_continuation(state, op_id, saved, completion)
            }
            pending_ops::PO_KIND_CHDIR_CONT => {
                crate::fileops::backing::complete_chdir_continuation(
                    state, op_id, saved, completion,
                )
            }
            pending_ops::PO_KIND_STATVFS_CONT => {
                crate::fileops::backing::complete_statvfs_continuation(
                    state, op_id, saved, completion,
                )
            }
            pending_ops::PO_KIND_MOUNT_CONT => {
                crate::fileops::backing::complete_mount_continuation(
                    state, op_id, saved, completion,
                )
            }
            pending_ops::PO_KIND_UMOUNT_CONT => {
                crate::fileops::backing::complete_umount_continuation(
                    state, op_id, saved, completion,
                )
            }
            pending_ops::PO_KIND_RESOLVE_PATH_BACKING_CONT => {
                crate::fileops::backing::complete_resolve_path_backing_continuation(
                    state, op_id, saved, completion,
                )
            }
            _ => {
                let reply_slot = pending_ops::take_reply_and_free(op_id);
                if reply_slot != 0 {
                    let mut reply = TronaMsg::zeroed();
                    reply.label = uapi::TRONA_NOT_SUPPORTED;
                    crate::fileops::tty_wait::send_saved_reply(reply_slot, &raw const reply);
                }
                true
            }
        }
    }
}

pub(super) fn parse_pts_slave_path(path: &[u8]) -> Option<u32> {
    let tail = path.strip_prefix(b"/dev/pts/")?;
    if tail.is_empty() || tail.contains(&b'/') {
        return None;
    }

    let mut value = 0u32;
    for byte in tail {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((byte - b'0') as u32)?;
    }
    Some(value)
}

pub(super) fn lookup_live_pty_generation(_state: &VfsState, pty_id: u32) -> Option<u32> {
    if crate::posix_ttysrv_ep() == 0 {
        return None;
    }

    let mut req = TronaMsg::zeroed();
    let mut reply = TronaMsg::zeroed();
    req.label = POSIX_TTYSRV_PTY_LOOKUP;
    req.length = 1;
    req.regs[0] = pty_id as u64;
    let err = unsafe {
        ipc::call_ctx(
            crate::ipc_ctx(),
            crate::posix_ttysrv_ep(),
            &raw const req,
            &raw mut reply,
        )
    };
    if err != 0 || reply.label != uapi::TRONA_OK {
        None
    } else {
        Some(reply.regs[0] as u32)
    }
}

/// Sync tail of `ensure_pts_slave_vnode`. Given a freshly-fetched
/// `generation` (from a `POSIX_TTYSRV_PTY_LOOKUP` reply, deferred or
/// inline), refresh the `/dev/pts/<id>` vnode in the bootstrap
/// namespace, creating it if absent. Returns `None` when the bootstrap
/// `/dev/pts` mount is missing or scratch slots are exhausted.
pub(super) fn ensure_pts_slave_vnode_with_generation(
    state: &mut VfsState,
    pty_id: u32,
    generation: u32,
) -> Option<VnodeHandle> {
    let pts_dir = state.bootstrap_lookup_path(b"/dev/pts")?;
    let (pts_mount, pts_fs_id) = {
        let vnode = state.vnodes.get(pts_dir)?;
        (vnode.mount.handle, vnode.fs_instance_id)
    };
    if !pts_mount.is_valid() {
        return None;
    }

    let mut name = [0u8; 16];
    let mut idx = name.len();
    let mut value = pty_id;
    loop {
        idx -= 1;
        name[idx] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let name = &name[idx..];

    if let Some(vh) = state.bootstrap_lookup_child(pts_dir, name) {
        let old_key = state
            .vnodes
            .get(vh)
            .map(|vnode| vnode.vnode_key())
            .unwrap_or(crate::vfs_core::identity::VnodeKey::INVALID);
        if let Some(vnode) = state.vnodes.get_mut(vh) {
            vnode.backend_seq = generation;
            vnode.id = crate::vfs_core::device::device_inode(
                crate::vfs_core::device::DN_PTY_SLAVE,
                pty_id,
            );
            vnode.mode = (trona_posix::consts::S_IFCHR as u32) | 0o666;
        }
        state.refresh_vnode_key(vh, old_key);
        return Some(vh);
    }

    let vh = state.create_bootstrap_char_device(
        pts_dir,
        pts_mount,
        pts_fs_id,
        name,
        (trona_posix::consts::S_IFCHR as u32) | 0o666,
        crate::vfs_core::device::DN_PTY_SLAVE,
        pty_id,
        generation,
    )?;
    if let Some(vnode) = state.vnodes.get_mut(vh) {
        vnode.id =
            crate::vfs_core::device::device_inode(crate::vfs_core::device::DN_PTY_SLAVE, pty_id);
        vnode.backend_seq = generation;
    }
    state.cache_vnode_key(vh);
    Some(vh)
}

/// Resolve `/dev/pts/<pty_id>` to its slave-side vnode by deferring a
/// `POSIX_TTYSRV_PTY_LOOKUP` RPC onto a worker thread. The owner
/// returns `VfsOpResult::Deferred(op_id)`; once the worker pushes the
/// completion `complete_namei_resume` runs the
/// `NAMEI_STEP_AFTER_PTS_LOOKUP` arm in `lookup_path_dynamic_resume`,
/// which fishes the generation out of the reply and chains into
/// `ensure_pts_slave_vnode_with_generation`.
///
/// The PendingOp is allocated with a placeholder reply slot (`0`).
/// The caller's syscall handler — once it has been ported to the
/// continuation framework — transfers its own reply slot onto the op
/// and switches `kind` to the appropriate `PO_KIND_*_CONT` so the
/// final reply lands at the originating client. Until that port is
/// done, the deferred path simply gets dropped on completion (the
/// reply slot is `0`); the inline-sync fallback in `lookup_live_pty_generation`
/// still services callers that have not migrated.
pub(super) fn ensure_pts_slave_vnode(
    state: &mut VfsState,
    pty_id: u32,
) -> VfsResult<Option<VnodeHandle>> {
    let _ = state;
    if crate::posix_ttysrv_ep() == 0 {
        return Ok(VfsOpResult::Complete(None));
    }
    let badge = 0u64;
    let cli_handle = ClientHandle::INVALID;
    let Some(op_id) =
        (unsafe { pending_ops::alloc(pending_ops::PO_KIND_NAMEI_RESUME, badge, cli_handle, 0) })
    else {
        return Ok(VfsOpResult::Complete(None));
    };
    // The PendingOp's typed payload is left as placeholder (empty path,
    // aux=NONE). The syscall handler that adopts this op for
    // continuation overwrites `saved.path` with its abs_path and
    // `saved.aux` with its `PO_KIND_*_CONT` body. `pty_id` is carried
    // on the backend job's `ctx.data[0]` and re-extracted in the
    // `NAMEI_STEP_AFTER_PTS_LOOKUP` resume arm via
    // `completion.ctx.data[0]`, so neither aux.pts nor a path stash is
    // needed here.
    let saved_ok = unsafe {
        save_namei_resume_state(
            op_id,
            crate::arena::Handle::<crate::vfs_core::vnode::Vnode>::new(0, 0),
            &[],
            0,
            0,
            false,
            false,
            false,
            false,
            NAMEI_STEP_AFTER_PTS_LOOKUP,
            NAMEI_AUX_NONE,
            namei_aux_none(),
        )
    };
    if !saved_ok {
        unsafe {
            let _ = pending_ops::take_reply_and_free(op_id);
        }
        return Ok(VfsOpResult::Complete(None));
    }

    let mut req = TronaMsg::zeroed();
    req.label = POSIX_TTYSRV_PTY_LOOKUP;
    req.length = 1;
    req.regs[0] = pty_id as u64;
    let mut ctx = super::backend_rpc::BackendOpCtx::zeroed();
    ctx.data[0] = pty_id as u64;
    let job = super::backend_rpc::PendingBackendJob {
        target_ep: crate::posix_ttysrv_ep(),
        op_kind: super::backend_rpc::BACKEND_OP_TTYSRV_GET_GENERATION,
        payload_out_bytes: 0,
        op_id: op_id.raw(),
        request: req,
        ctx,
    };
    if !super::backend_rpc::try_enqueue_job(job) {
        unsafe {
            let _ = pending_ops::take_reply_and_free(op_id);
        }
        return Ok(VfsOpResult::Complete(None));
    }

    Ok(VfsOpResult::Deferred(op_id))
}

pub(super) fn lookup_path_dynamic_for_client(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    path: &[u8],
    no_follow: bool,
) -> VfsResult<Option<VnodeHandle>> {
    if let Some(vh) = crate::fs::procfs::lookup_dynamic_path(state, cli_handle, path, no_follow) {
        return Ok(VfsOpResult::Complete(Some(vh)));
    }
    if let Some(pty_id) = parse_pts_slave_path(path) {
        return ensure_pts_slave_vnode(state, pty_id);
    }

    let personality = state
        .clients
        .get(cli_handle)
        .map(|client| client.personality)
        .unwrap_or(PERS_POSIX);
    let ignore_case = personality == PERS_WIN32;
    let skip_posix_only = personality == PERS_WIN32;
    let skip_win32_only = personality != PERS_WIN32;
    lookup_path_dynamic_inner(
        state,
        path,
        0,
        !no_follow,
        ignore_case,
        skip_posix_only,
        skip_win32_only,
    )
}

pub(super) fn lookup_path_dynamic_absolute(
    state: &mut VfsState,
    path: &[u8],
    no_follow: bool,
) -> VfsResult<Option<VnodeHandle>> {
    if path.first().copied() != Some(b'/') {
        return Ok(VfsOpResult::Complete(None));
    }
    lookup_path_dynamic_inner(state, path, 0, !no_follow, false, false, false)
}
