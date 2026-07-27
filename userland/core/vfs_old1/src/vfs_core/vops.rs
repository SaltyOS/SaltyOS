// SPDX-License-Identifier: GPL-2.0-only
//! Vnode-op dispatch.
//!
//! The vops layer is the seam between owner-side namei/fileops and the
//! per-backend implementations. Every backend hook that may perform a
//! blocking RPC (procfs/devfs/saltyfs/socket/shm) returns a
//! [`VfsResult<T>`] — either `Complete(value)` for a synchronous
//! finish or `Deferred(op_id)` to indicate the call has been routed
//! through the worker pool and the caller must suspend the current
//! dispatch (typically by setting `reply.label = REPLY_DEFERRED_LABEL`).
//! Pure-state hooks (`build_path`, `validate_open_regular`,
//! `supports_pager_backing`) keep their synchronous shape.

use crate::owner::VfsState;
use crate::owner::pending_ops::PendingOpId;
use uapi::{
    TRONA_BUSY, TRONA_CROSS_DEVICE, TRONA_INVALID_OPERATION, TRONA_NOT_SUPPORTED, TRONA_OK,
    TRONA_OUT_OF_MEMORY,
};

use super::vnode::VnodeHandle;

/// Result of a vnode operation that may complete synchronously or be
/// deferred to a worker. `Deferred(op_id)` carries the pending-op
/// handle so the dispatch site can report `REPLY_DEFERRED_LABEL`.
#[derive(Clone, Copy)]
pub(crate) enum VfsOpResult<T> {
    Complete(T),
    Deferred(PendingOpId),
}

/// Standard vnode-op return: either a synchronous success / deferred
/// reservation, or an immediate error code.
pub(crate) type VfsResult<T> = Result<VfsOpResult<T>, u64>;

/// Lift a synchronous unit-returning code (`TRONA_OK` or an error) to
/// the deferred-capable shape used by mutation hooks.
#[inline]
pub(crate) fn unit_from_code(code: u64) -> VfsResult<()> {
    if code == TRONA_OK {
        Ok(VfsOpResult::Complete(()))
    } else {
        Err(code)
    }
}

/// Collapse a `VfsResult<()>` to a single u64 label suitable for
/// `reply.label`. `Deferred` becomes `REPLY_DEFERRED_LABEL` so the
/// owner loop suppresses the synchronous reply and waits for the
/// deferred completion.
#[inline]
pub(crate) fn label_from_unit_result(r: VfsResult<()>) -> u64 {
    match r {
        Ok(VfsOpResult::Complete(())) => TRONA_OK,
        Ok(VfsOpResult::Deferred(_)) => crate::fileops::tty_wait::REPLY_DEFERRED_LABEL,
        Err(code) => code,
    }
}

/// Unwrap a `VfsResult<T>` for sync-only callers: `Deferred` is
/// reported as the deferred-reply marker label, complete values are
/// surfaced, errors propagate. Caller is expected to feed the
/// `Err(REPLY_DEFERRED_LABEL)` case into `reply.label` so the owner
/// loop suppresses the synchronous reply.
#[inline]
pub(crate) fn into_value_or_label<T>(r: VfsResult<T>) -> Result<T, u64> {
    match r {
        Ok(VfsOpResult::Complete(v)) => Ok(v),
        Ok(VfsOpResult::Deferred(_)) => Err(crate::fileops::tty_wait::REPLY_DEFERRED_LABEL),
        Err(e) => Err(e),
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ReaddirEntry {
    pub(crate) next_cursor: u64,
    pub(crate) eof_after: bool,
    pub(crate) name_len: u8,
    pub(crate) ino: u64,
    pub(crate) d_type: u8,
}

pub(crate) type ReaddirResult = VfsResult<Option<ReaddirEntry>>;

/// Per-backend vnode operations. Every RPC-capable hook returns a
/// `VfsResult<T>`; pure-state hooks (`build_path`,
/// `validate_open_regular`, `supports_pager_backing`) stay
/// synchronous.
#[repr(C)]
pub(crate) struct VnodeOps {
    pub(crate) lookup_child:
        Option<fn(&mut VfsState, VnodeHandle, &[u8]) -> VfsResult<Option<VnodeHandle>>>,
    pub(crate) build_path: Option<fn(&VfsState, VnodeHandle, &mut [u8]) -> Option<usize>>,
    pub(crate) ensure_symlink_target: Option<fn(&mut VfsState, VnodeHandle) -> VfsResult<bool>>,
    pub(crate) readlink_inline: Option<
        fn(
            &VfsState,
            Option<crate::server::types::ClientHandle>,
            VnodeHandle,
            *mut u8,
            usize,
        ) -> VfsResult<usize>,
    >,
    pub(crate) read_regular: Option<
        unsafe fn(
            &VfsState,
            Option<crate::server::types::ClientHandle>,
            VnodeHandle,
            u64,
            *mut u8,
            usize,
        ) -> VfsResult<usize>,
    >,
    pub(crate) write_regular:
        Option<unsafe fn(&mut VfsState, VnodeHandle, u64, *const u8, usize) -> VfsResult<u64>>,
    pub(crate) create_regular_child:
        Option<fn(&mut VfsState, VnodeHandle, &[u8], u32) -> VfsResult<VnodeHandle>>,
    pub(crate) mkdir_child:
        Option<fn(&mut VfsState, VnodeHandle, &[u8], u32) -> VfsResult<VnodeHandle>>,
    pub(crate) symlink_child:
        Option<fn(&mut VfsState, VnodeHandle, &[u8], &[u8]) -> VfsResult<VnodeHandle>>,
    pub(crate) remove_child: Option<fn(&mut VfsState, VnodeHandle, &[u8], bool) -> VfsResult<()>>,
    pub(crate) rename_child:
        Option<fn(&mut VfsState, VnodeHandle, &[u8], VnodeHandle, &[u8]) -> VfsResult<()>>,
    pub(crate) link_vnode_into:
        Option<fn(&mut VfsState, VnodeHandle, VnodeHandle, &[u8]) -> VfsResult<()>>,
    pub(crate) set_mode: Option<fn(&mut VfsState, VnodeHandle, u32) -> VfsResult<()>>,
    pub(crate) set_owner: Option<fn(&mut VfsState, VnodeHandle, u32, u32) -> VfsResult<()>>,
    pub(crate) set_times:
        Option<fn(&mut VfsState, VnodeHandle, Option<u64>, Option<u64>) -> VfsResult<()>>,
    pub(crate) truncate: Option<fn(&mut VfsState, VnodeHandle, u64) -> VfsResult<()>>,
    pub(crate) validate_open_regular: Option<fn(&VfsState, VnodeHandle, u32) -> u64>,
    pub(crate) readdir_dir: Option<
        fn(
            &VfsState,
            Option<crate::server::types::ClientHandle>,
            VnodeHandle,
            u64,
            bool,
            &mut [u8; 128],
        ) -> ReaddirResult,
    >,
    pub(crate) supports_pager_backing: Option<fn(&VfsState, VnodeHandle) -> bool>,
}

impl VnodeOps {
    pub(crate) const fn empty() -> Self {
        Self {
            lookup_child: None,
            build_path: None,
            ensure_symlink_target: None,
            readlink_inline: None,
            read_regular: None,
            write_regular: None,
            create_regular_child: None,
            mkdir_child: None,
            symlink_child: None,
            remove_child: None,
            rename_child: None,
            link_vnode_into: None,
            set_mode: None,
            set_owner: None,
            set_times: None,
            truncate: None,
            validate_open_regular: None,
            readdir_dir: None,
            supports_pager_backing: None,
        }
    }
}

static EMPTY_VOPS: VnodeOps = VnodeOps::empty();

#[inline]
pub(crate) fn empty_vops() -> *const () {
    &raw const EMPTY_VOPS as *const VnodeOps as *const ()
}

#[inline]
fn table_from_ptr(ptr: *const ()) -> Option<&'static VnodeOps> {
    if ptr.is_null() {
        None
    } else {
        // SAFETY: `Vnode.ops` is populated from static `VnodeOps` tables.
        Some(unsafe { &*(ptr as *const VnodeOps) })
    }
}

#[inline]
fn vnode_ops_ptr(state: &VfsState, vnode: VnodeHandle) -> *const () {
    state
        .vnodes
        .get(vnode)
        .map(|vn| vn.ops)
        .unwrap_or(core::ptr::null())
}

pub(crate) fn lookup_child(
    state: &mut VfsState,
    parent: VnodeHandle,
    name: &[u8],
) -> VfsResult<Option<VnodeHandle>> {
    let ops_ptr = vnode_ops_ptr(state, parent);
    let Some(ops) = table_from_ptr(ops_ptr) else {
        return Ok(VfsOpResult::Complete(None));
    };
    match ops.lookup_child {
        Some(callback) => callback(state, parent, name),
        None => Ok(VfsOpResult::Complete(None)),
    }
}

pub(crate) fn build_path_for_vnode(
    state: &VfsState,
    vnode: VnodeHandle,
    out: &mut [u8],
) -> Option<usize> {
    let ops_ptr = vnode_ops_ptr(state, vnode);
    let ops = table_from_ptr(ops_ptr)?;
    let callback = ops.build_path?;
    callback(state, vnode, out)
}

pub(crate) fn ensure_symlink_target(state: &mut VfsState, vnode: VnodeHandle) -> VfsResult<bool> {
    let ops_ptr = vnode_ops_ptr(state, vnode);
    let Some(ops) = table_from_ptr(ops_ptr) else {
        return Ok(VfsOpResult::Complete(false));
    };
    let Some(callback) = ops.ensure_symlink_target else {
        return Ok(VfsOpResult::Complete(false));
    };
    callback(state, vnode)
}

pub(crate) fn readlink_inline(
    state: &VfsState,
    cli_handle: Option<crate::server::types::ClientHandle>,
    vnode: VnodeHandle,
    out: *mut u8,
    cap: usize,
) -> Option<VfsResult<usize>> {
    let ops_ptr = vnode_ops_ptr(state, vnode);
    let ops = table_from_ptr(ops_ptr)?;
    let callback = ops.readlink_inline?;
    Some(callback(state, cli_handle, vnode, out, cap))
}

pub(crate) unsafe fn read_regular(
    state: &VfsState,
    cli_handle: Option<crate::server::types::ClientHandle>,
    vnode: VnodeHandle,
    offset: u64,
    out: *mut u8,
    cap: usize,
) -> Option<VfsResult<usize>> {
    let ops_ptr = vnode_ops_ptr(state, vnode);
    let ops = table_from_ptr(ops_ptr)?;
    match ops.read_regular {
        Some(callback) => Some(unsafe { callback(state, cli_handle, vnode, offset, out, cap) }),
        None => Some(Err(TRONA_NOT_SUPPORTED)),
    }
}

pub(crate) unsafe fn write_regular(
    state: &mut VfsState,
    vnode: VnodeHandle,
    offset: u64,
    src: *const u8,
    len: usize,
) -> Option<VfsResult<u64>> {
    let ops_ptr = vnode_ops_ptr(state, vnode);
    let ops = table_from_ptr(ops_ptr)?;
    match ops.write_regular {
        Some(callback) => Some(unsafe { callback(state, vnode, offset, src, len) }),
        None => Some(Err(TRONA_NOT_SUPPORTED)),
    }
}

pub(crate) fn create_regular_child(
    state: &mut VfsState,
    parent: VnodeHandle,
    name: &[u8],
    mode: u32,
    personality: u8,
) -> VfsResult<VnodeHandle> {
    let ops_ptr = vnode_ops_ptr(state, parent);
    if let Some(ops) = table_from_ptr(ops_ptr) {
        if let Some(callback) = ops.create_regular_child {
            return callback(state, parent, name, mode);
        }
        return Err(TRONA_NOT_SUPPORTED);
    }
    state
        .bootstrap_create_regular_child_for_personality(parent, name, mode, personality)
        .map(VfsOpResult::Complete)
}

pub(crate) fn mkdir_child(
    state: &mut VfsState,
    parent: VnodeHandle,
    name: &[u8],
    mode: u32,
    personality: u8,
) -> VfsResult<VnodeHandle> {
    let ops_ptr = vnode_ops_ptr(state, parent);
    if let Some(ops) = table_from_ptr(ops_ptr) {
        if let Some(callback) = ops.mkdir_child {
            return callback(state, parent, name, mode);
        }
        return Err(TRONA_NOT_SUPPORTED);
    }
    state
        .bootstrap_mkdir_child_for_personality(parent, name, mode, personality)
        .map(VfsOpResult::Complete)
}

pub(crate) fn symlink_child(
    state: &mut VfsState,
    parent: VnodeHandle,
    name: &[u8],
    target: &[u8],
    personality: u8,
) -> VfsResult<VnodeHandle> {
    let ops_ptr = vnode_ops_ptr(state, parent);
    if let Some(ops) = table_from_ptr(ops_ptr) {
        if let Some(callback) = ops.symlink_child {
            return callback(state, parent, name, target);
        }
        return Err(TRONA_NOT_SUPPORTED);
    }
    state
        .bootstrap_create_symlink_child_for_personality(
            parent,
            name,
            (trona_posix::consts::S_IFLNK as u32) | 0o777,
            target,
            personality,
        )
        .map(VfsOpResult::Complete)
}

pub(crate) fn remove_child(
    state: &mut VfsState,
    parent: VnodeHandle,
    name: &[u8],
    want_dir: bool,
    personality: u8,
) -> VfsResult<()> {
    // Mountpoint / root guard: every dispatch path needs to refuse
    // unlink / rmdir on a vnode that another mount currently covers,
    // otherwise the bootstrap-side `bootstrap_remove_child_*` guard
    // we used to rely on gets bypassed when the parent has a backend
    // ops table. Resolve the candidate child via both the bootstrap
    // entry table and the backend lookup so tmpfs / saltyfs children
    // count too.
    let ignore_case = crate::owner::VfsState::personality_ignore_case(personality);
    let ops_ptr = vnode_ops_ptr(state, parent);
    let candidate = state
        .bootstrap_lookup_child_with_case(parent, name, ignore_case)
        .or_else(|| {
            if table_from_ptr(ops_ptr).is_some() {
                return None;
            }
            match lookup_child(state, parent, name) {
                Ok(VfsOpResult::Complete(Some(vh))) => Some(vh),
                _ => None,
            }
        });
    if let Some(child) = candidate {
        if let Some(vn) = state.vnodes.get(child) {
            if (vn.flags & crate::vfs_core::vnode::VN_ROOT) != 0
                || vn.covered_by.id != crate::vfs_core::identity::FsInstanceId::INVALID
            {
                return Err(TRONA_BUSY);
            }
        }
    }
    if let Some(ops) = table_from_ptr(ops_ptr) {
        if let Some(callback) = ops.remove_child {
            return callback(state, parent, name, want_dir);
        }
        return Err(TRONA_NOT_SUPPORTED);
    }
    unit_from_code(state.bootstrap_remove_child_for_personality(
        parent,
        name,
        want_dir,
        personality,
    ))
}

pub(crate) fn rename_child(
    state: &mut VfsState,
    old_parent: VnodeHandle,
    old_name: &[u8],
    new_parent: VnodeHandle,
    new_name: &[u8],
    personality: u8,
) -> VfsResult<()> {
    let old_ops_ptr = vnode_ops_ptr(state, old_parent);
    let new_ops_ptr = vnode_ops_ptr(state, new_parent);
    if old_ops_ptr == new_ops_ptr {
        if let Some(ops) = table_from_ptr(old_ops_ptr) {
            if let Some(callback) = ops.rename_child {
                return callback(state, old_parent, old_name, new_parent, new_name);
            }
            return Err(TRONA_NOT_SUPPORTED);
        } else {
            return unit_from_code(state.bootstrap_rename_child_for_personality(
                old_parent,
                old_name,
                new_parent,
                new_name,
                personality,
            ));
        }
    }
    Err(TRONA_CROSS_DEVICE)
}

pub(crate) fn link_vnode_into(
    state: &mut VfsState,
    source: VnodeHandle,
    new_parent: VnodeHandle,
    new_name: &[u8],
    personality: u8,
) -> VfsResult<()> {
    let source_ops_ptr = vnode_ops_ptr(state, source);
    let parent_ops_ptr = vnode_ops_ptr(state, new_parent);
    if source_ops_ptr == parent_ops_ptr {
        if let Some(ops) = table_from_ptr(source_ops_ptr) {
            if let Some(callback) = ops.link_vnode_into {
                return callback(state, source, new_parent, new_name);
            }
            return Err(TRONA_NOT_SUPPORTED);
        } else {
            return unit_from_code(state.bootstrap_link_vnode_child_for_personality(
                source,
                new_parent,
                new_name,
                personality,
            ));
        }
    }
    Err(TRONA_CROSS_DEVICE)
}

pub(crate) fn set_mode(state: &mut VfsState, vnode: VnodeHandle, mode: u32) -> VfsResult<()> {
    let ops_ptr = vnode_ops_ptr(state, vnode);
    if let Some(ops) = table_from_ptr(ops_ptr) {
        if let Some(callback) = ops.set_mode {
            return callback(state, vnode, mode);
        }
        return Err(TRONA_INVALID_OPERATION);
    }
    unit_from_code(state.bootstrap_set_mode_vnode(vnode, mode))
}

pub(crate) fn set_owner(
    state: &mut VfsState,
    vnode: VnodeHandle,
    uid: u32,
    gid: u32,
) -> VfsResult<()> {
    let ops_ptr = vnode_ops_ptr(state, vnode);
    if let Some(ops) = table_from_ptr(ops_ptr) {
        if let Some(callback) = ops.set_owner {
            return callback(state, vnode, uid, gid);
        }
        return Err(TRONA_INVALID_OPERATION);
    }
    unit_from_code(state.bootstrap_set_owner_vnode(vnode, uid, gid))
}

pub(crate) fn set_times(
    state: &mut VfsState,
    vnode: VnodeHandle,
    atime: Option<u64>,
    mtime: Option<u64>,
) -> VfsResult<()> {
    let ops_ptr = vnode_ops_ptr(state, vnode);
    if let Some(ops) = table_from_ptr(ops_ptr) {
        if let Some(callback) = ops.set_times {
            return callback(state, vnode, atime, mtime);
        }
        return Err(TRONA_INVALID_OPERATION);
    }
    unit_from_code(state.bootstrap_set_times_vnode(vnode, atime, mtime))
}

pub(crate) fn truncate(state: &mut VfsState, vnode: VnodeHandle, new_size: u64) -> VfsResult<()> {
    let ops_ptr = vnode_ops_ptr(state, vnode);
    if let Some(ops) = table_from_ptr(ops_ptr) {
        if let Some(callback) = ops.truncate {
            return callback(state, vnode, new_size);
        }
        return Err(TRONA_INVALID_OPERATION);
    }
    if state.bootstrap_resize_file(vnode, new_size) {
        Ok(VfsOpResult::Complete(()))
    } else {
        Err(TRONA_OUT_OF_MEMORY)
    }
}

pub(crate) fn validate_open_regular(state: &VfsState, vnode: VnodeHandle, flags: u32) -> u64 {
    let ops_ptr = vnode_ops_ptr(state, vnode);
    if let Some(ops) = table_from_ptr(ops_ptr) {
        if let Some(callback) = ops.validate_open_regular {
            return callback(state, vnode, flags);
        }
    }
    TRONA_OK
}

pub(crate) fn readdir_dir(
    state: &VfsState,
    cli_handle: Option<crate::server::types::ClientHandle>,
    vnode: VnodeHandle,
    cursor: u64,
    ignore_case: bool,
    name_out: &mut [u8; 128],
) -> Option<ReaddirResult> {
    let ops_ptr = vnode_ops_ptr(state, vnode);
    let ops = table_from_ptr(ops_ptr)?;
    let callback = ops.readdir_dir?;
    Some(callback(
        state,
        cli_handle,
        vnode,
        cursor,
        ignore_case,
        name_out,
    ))
}

pub(crate) fn supports_pager_backing(state: &VfsState, vnode: VnodeHandle) -> bool {
    let ops_ptr = vnode_ops_ptr(state, vnode);
    if let Some(ops) = table_from_ptr(ops_ptr) {
        if let Some(callback) = ops.supports_pager_backing {
            return callback(state, vnode);
        }
    }
    true
}
