// SPDX-License-Identifier: GPL-2.0-only
//! Synchronous bootstrap open path.

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use trona_protocol::posix::*;
use trona_runtime::core::server_consts::TRONA_NOT_CONNECTED;
use uapi::*;

use crate::owner::VfsState;
use crate::server::client::{
    MAX_PATH_LEN, extract_path, normalize_path_at_owned, normalize_path_owned,
};
use crate::server::types::{ClientHandle, OBJ_DIRECTORY, OBJ_FILE};
use crate::vfs_core::vnode::{VT_CHR, VT_DIR, VT_FIFO, VT_REG};

pub(crate) unsafe fn open_abs_path_as_slot(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    force_directory: bool,
    flags: u32,
    mode: u32,
    abs_path: &[u8],
    reply: *mut TronaMsg,
) {
    unsafe {
        let resolved = match state.lookup_path_dynamic_for_client(cli_handle, abs_path, false) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(opt)) => opt,
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                open_continuation_adopt(
                    state,
                    cli_handle,
                    op_id,
                    abs_path,
                    flags,
                    mode,
                    force_directory,
                    crate::owner::namei::OPEN_STAGE_LOOKUP,
                    0,
                    reply,
                );
                return;
            }
            Err(err) => {
                (*reply).label = err;
                (*reply).length = 0;
                return;
            }
        };
        match open_continue_after_lookup(
            state,
            cli_handle,
            force_directory,
            flags,
            mode,
            abs_path,
            resolved,
            reply,
        ) {
            OpenStepOutcome::Done => {}
            OpenStepOutcome::DeferredAt(op_id, stage, leaf_offset) => {
                open_continuation_adopt(
                    state,
                    cli_handle,
                    op_id,
                    abs_path,
                    flags,
                    mode,
                    force_directory,
                    stage,
                    leaf_offset,
                    reply,
                );
            }
        }
    }
}

/// Adopt a deferred op produced by the namei walk, `lookup_parent`,
/// `create_regular_child`, or `truncate` for the open continuation.
/// Stamps `PO_KIND_OPEN_CONT`, transfers this caller's reply slot, and
/// stashes the per-stage `OpenContBody` in the payload aux. The
/// `complete_open_continuation` resume picks the matching tail from
/// `body.stage`.
unsafe fn open_continuation_adopt(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    op_id: crate::owner::pending_ops::PendingOpId,
    abs_path: &[u8],
    flags: u32,
    mode: u32,
    force_directory: bool,
    stage: u8,
    leaf_offset: u16,
    reply: *mut TronaMsg,
) {
    let body = crate::owner::namei::OpenContBody {
        flags,
        mode,
        dirfd_packed: 0,
        result_fd_hint: -1,
        force_directory: if force_directory { 1 } else { 0 },
        stage,
        leaf_offset,
        _pad: [0; 72],
    };
    let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
    let ok = unsafe {
        crate::owner::continuation::adopt_deferred_op_for_continuation(
            op_id,
            crate::owner::pending_ops::PO_KIND_OPEN_CONT,
            badge,
            cli_handle,
            reply,
            abs_path,
            crate::owner::namei::NAMEI_AUX_OPEN,
            crate::owner::namei::namei_aux_open(body),
        )
    };
    if !ok {
        unsafe {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
        }
    }
}

/// Sync tail after the path lookup has produced `resolved`. Handles
/// O_CREAT / O_EXCL pre-checks, dispatches to the parent-lookup
/// continuation when O_CREAT needs to materialise a new entry, and
/// otherwise drives `open_finalize_or_defer`.
unsafe fn open_continue_after_lookup(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    force_directory: bool,
    flags: u32,
    mode: u32,
    abs_path: &[u8],
    resolved: Option<crate::vfs_core::vnode::VnodeHandle>,
    reply: *mut TronaMsg,
) -> OpenStepOutcome {
    unsafe {
        let pipefs_named_path = abs_path.starts_with(b"/pipe/") && abs_path.len() > b"/pipe/".len();
        if pipefs_named_path && (flags & O_TRUNC) != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return OpenStepOutcome::Done;
        }
        let existed_before = resolved.is_some();
        if existed_before && (flags & O_CREAT) != 0 && (flags & O_EXCL) != 0 {
            (*reply).label = TRONA_ALREADY_EXISTS;
            (*reply).length = 0;
            return OpenStepOutcome::Done;
        }
        if resolved.is_none() && !force_directory && (flags & O_CREAT) != 0 {
            if crate::fileops::device::is_device_namespace_path(abs_path) {
                (*reply).label = TRONA_NOT_SUPPORTED;
                (*reply).length = 0;
                return OpenStepOutcome::Done;
            }
            match state.lookup_parent_for_client_deferred(cli_handle, abs_path) {
                Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(parent_lookup))) => {
                    let parent_vh = parent_lookup.parent.handle;
                    let leaf_offset = parent_lookup.leaf_offset as u16;
                    return open_continue_after_parent_lookup(
                        state,
                        cli_handle,
                        force_directory,
                        flags,
                        mode,
                        abs_path,
                        parent_vh,
                        leaf_offset,
                        reply,
                    );
                }
                Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                    (*reply).label = TRONA_NOT_FOUND;
                    (*reply).length = 0;
                    return OpenStepOutcome::Done;
                }
                Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                    return OpenStepOutcome::DeferredAt(
                        op_id,
                        crate::owner::namei::OPEN_STAGE_PARENT_LOOKUP,
                        leaf_offset_of(abs_path),
                    );
                }
                Err(err) => {
                    (*reply).label = err;
                    (*reply).length = 0;
                    return OpenStepOutcome::Done;
                }
            }
        }

        let Some(vh) = resolved else {
            (*reply).label = TRONA_NOT_FOUND;
            (*reply).length = 0;
            return OpenStepOutcome::Done;
        };
        open_finalize_or_defer(
            state,
            cli_handle,
            force_directory,
            flags,
            mode,
            abs_path,
            vh,
            false,
            reply,
        )
    }
}

/// Sync tail after `lookup_parent` has resolved. Calls
/// `create_regular_child` (or the bootstrap pipefs creator) and
/// dispatches the result. A `Deferred` create transitions to the
/// `OPEN_STAGE_CREATE` continuation; the new child vnode arrives in
/// `saved.current_packed` on resume.
unsafe fn open_continue_after_parent_lookup(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    force_directory: bool,
    flags: u32,
    mode: u32,
    abs_path: &[u8],
    parent_vh: crate::vfs_core::vnode::VnodeHandle,
    leaf_offset: u16,
    reply: *mut TronaMsg,
) -> OpenStepOutcome {
    unsafe {
        let pipefs_named_path = abs_path.starts_with(b"/pipe/") && abs_path.len() > b"/pipe/".len();
        let personality = state.client_personality(cli_handle);
        let create_result = if pipefs_named_path {
            state
                .bootstrap_create_fifo_path_for_personality(
                    abs_path,
                    (trona_posix::consts::S_IFIFO as u32) | 0o666,
                    personality,
                )
                .map(crate::vfs_core::vops::VfsOpResult::Complete)
        } else {
            crate::vfs_core::vops::create_regular_child(
                state,
                parent_vh,
                &abs_path[leaf_offset as usize..],
                (trona_posix::consts::S_IFREG as u32) | (mode & 0o7777),
                personality,
            )
        };
        match create_result {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(child_vh)) => open_finalize_or_defer(
                state,
                cli_handle,
                force_directory,
                flags,
                mode,
                abs_path,
                child_vh,
                false,
                reply,
            ),
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => OpenStepOutcome::DeferredAt(
                op_id,
                crate::owner::namei::OPEN_STAGE_CREATE,
                leaf_offset,
            ),
            Err(err) => {
                (*reply).label = err;
                (*reply).length = 0;
                OpenStepOutcome::Done
            }
        }
    }
}

/// Run the open sync tail on `vh`. If `truncate` yields a deferred op,
/// adopt it as `OPEN_STAGE_TRUNCATE` so the worker re-enters
/// `complete_open_continuation` to finish fd allocation. `truncate_done`
/// is set on the resume path so the truncate stage runs at most once.
unsafe fn open_finalize_or_defer(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    force_directory: bool,
    flags: u32,
    mode: u32,
    abs_path: &[u8],
    vh: crate::vfs_core::vnode::VnodeHandle,
    truncate_done: bool,
    reply: *mut TronaMsg,
) -> OpenStepOutcome {
    unsafe {
        match open_finalize_with_vnode(
            state,
            cli_handle,
            force_directory,
            flags,
            mode,
            abs_path,
            vh,
            truncate_done,
        ) {
            OpenFinalizeOutcome::Done(r) => {
                *reply = r;
                OpenStepOutcome::Done
            }
            OpenFinalizeOutcome::TruncateDeferred(op_id) => {
                OpenStepOutcome::DeferredAt(op_id, crate::owner::namei::OPEN_STAGE_TRUNCATE, 0)
            }
        }
    }
}

enum OpenFinalizeOutcome {
    Done(TronaMsg),
    TruncateDeferred(crate::owner::pending_ops::PendingOpId),
}

/// One step in the open continuation pipeline. `Done` means `reply`
/// already carries the wire response and the caller is finished;
/// `DeferredAt(op_id, stage, leaf_offset)` means a downstream vop
/// yielded — the caller decides whether to `open_continuation_adopt`
/// (sync entry) or `transition_to_chained_op_with_aux` (chained
/// completion-context entry).
enum OpenStepOutcome {
    Done,
    DeferredAt(
        crate::owner::pending_ops::PendingOpId,
        u8,  // OPEN_STAGE_*
        u16, // leaf_offset for STAGE_PARENT_LOOKUP / STAGE_CREATE
    ),
}

/// Last `/` index + 1, or 0 if there is no `/`. Used to compute
/// `leaf_offset` when `lookup_parent_for_client_deferred` yields —
/// the synchronous `ParentLookup.leaf_offset` is not available on
/// the deferred branch, so the caller must derive it from `abs_path`.
fn leaf_offset_of(abs_path: &[u8]) -> u16 {
    abs_path
        .iter()
        .rposition(|&b| b == b'/')
        .map(|p| (p + 1) as u16)
        .unwrap_or(0)
}

/// Sync tail of `open`/`openat`/`creat`/`opendir`. Runs once `vh` is
/// resolved (either inline or via the syscall continuation framework).
/// Returns `OpenFinalizeOutcome` so the caller can transition the
/// continuation onto a chained `OPEN_STAGE_TRUNCATE` op when the
/// regular-file truncate yields. Internal helpers that take a raw
/// reply pointer (`open_char_device_as_slot`, `defer_fifo_open`) are
/// called with a pointer to the local `reply` because they expect to
/// mutate in place. `truncate_done` is set on the resume path so the
/// truncate stage runs at most once.
unsafe fn open_finalize_with_vnode(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    force_directory: bool,
    flags: u32,
    mode: u32,
    abs_path: &[u8],
    vh: crate::vfs_core::vnode::VnodeHandle,
    truncate_done: bool,
) -> OpenFinalizeOutcome {
    let _ = mode;
    let pipefs_named_path = abs_path.starts_with(b"/pipe/") && abs_path.len() > b"/pipe/".len();
    let mut reply = TronaMsg::zeroed();
    unsafe {
        let Some(vnode) = state.vnodes.get(vh) else {
            reply.label = TRONA_NOT_FOUND;
            return OpenFinalizeOutcome::Done(reply);
        };
        if pipefs_named_path && vnode.vtype == VT_REG {
            reply.label = TRONA_NOT_SUPPORTED;
            return OpenFinalizeOutcome::Done(reply);
        }
        if vnode.vtype == VT_REG {
            let open_policy = crate::vfs_core::vops::validate_open_regular(state, vh, flags);
            if open_policy != TRONA_OK {
                reply.label = open_policy;
                return OpenFinalizeOutcome::Done(reply);
            }
        }

        if vnode.vtype == VT_REG {
            if let Some(shm) = state.shm_by_vnode(vh) {
                let accmode = flags & O_ACCMODE;
                if accmode > O_RDWR {
                    reply.label = TRONA_INVALID_ARGUMENT;
                    return OpenFinalizeOutcome::Done(reply);
                }
                if (flags & O_TRUNC) != 0 && !truncate_done {
                    if accmode == O_RDONLY {
                        reply.label = TRONA_INVALID_OPERATION;
                        return OpenFinalizeOutcome::Done(reply);
                    }
                    let current_pages = state.shm_state(shm).map(|s| s.num_pages).unwrap_or(0);
                    let shm_id = match state.shm_state(shm) {
                        Some(s) => s.id,
                        None => {
                            reply.label = TRONA_NOT_FOUND;
                            return OpenFinalizeOutcome::Done(reply);
                        }
                    };
                    if current_pages != 0 {
                        let mut mm_msg = TronaMsg::zeroed();
                        let mut mm_reply = TronaMsg::zeroed();
                        mm_msg.label = MM_SHM_DESTROY;
                        mm_msg.length = 1;
                        mm_msg.regs[0] = shm_id;
                        let err = trona_kernel::ipc::call_ctx(
                            crate::ipc_ctx(),
                            trona_runtime::client::caps::mmsrv_ep(),
                            &raw const mm_msg,
                            &raw mut mm_reply,
                        );
                        if err != 0 && mm_reply.label != TRONA_OK {
                            reply.label = if err != 0 {
                                TRONA_INVALID_OPERATION
                            } else {
                                mm_reply.label
                            };
                            return OpenFinalizeOutcome::Done(reply);
                        }
                        if let Some(shm_state) = state.shm_state_mut(shm) {
                            shm_state.num_pages = 0;
                        }
                    }
                    if let Some(vn) = state.vnodes.get_mut(vh) {
                        vn.size = 0;
                        vn.mtime_ns = vn.mtime_ns.saturating_add(1);
                    }
                }
                let Some(fd) = state.alloc_shm_client_slot(cli_handle, vh, shm, flags) else {
                    reply.label = TRONA_OUT_OF_MEMORY;
                    return OpenFinalizeOutcome::Done(reply);
                };
                reply.label = TRONA_OK;
                reply.length = 1;
                reply.regs[0] = fd as u64;
                return OpenFinalizeOutcome::Done(reply);
            }
        }

        if vnode.vtype == VT_DIR {
            let accmode = flags & O_ACCMODE;
            if accmode != O_RDONLY || (flags & (O_CREAT | O_TRUNC | O_EXCL | O_APPEND)) != 0 {
                reply.label = TRONA_IS_DIRECTORY;
                return OpenFinalizeOutcome::Done(reply);
            }
            if !force_directory {
                reply.label = TRONA_IS_DIRECTORY;
                return OpenFinalizeOutcome::Done(reply);
            }

            let Some(fd) = state.alloc_client_slot(cli_handle, vh, OBJ_DIRECTORY, flags) else {
                reply.label = TRONA_OUT_OF_MEMORY;
                return OpenFinalizeOutcome::Done(reply);
            };
            reply.label = TRONA_OK;
            reply.length = 1;
            reply.regs[0] = fd as u64;
            return OpenFinalizeOutcome::Done(reply);
        }

        if vnode.vtype == VT_CHR {
            if force_directory {
                reply.label = TRONA_NOT_DIRECTORY;
                return OpenFinalizeOutcome::Done(reply);
            }
            crate::fileops::device::open_char_device_as_slot(
                state,
                cli_handle,
                vh,
                flags,
                &raw mut reply,
            );
            return OpenFinalizeOutcome::Done(reply);
        }

        if vnode.vtype == VT_FIFO {
            if force_directory {
                reply.label = TRONA_NOT_DIRECTORY;
                return OpenFinalizeOutcome::Done(reply);
            }
            let accmode = flags & O_ACCMODE;
            if accmode > O_RDWR {
                reply.label = TRONA_INVALID_ARGUMENT;
                return OpenFinalizeOutcome::Done(reply);
            }
            if (flags & O_TRUNC) != 0 {
                reply.label = TRONA_INVALID_OPERATION;
                return OpenFinalizeOutcome::Done(reply);
            }
            let Some(pipe) = state.ensure_fifo_pipe_for_vnode(vh) else {
                reply.label = TRONA_OUT_OF_MEMORY;
                return OpenFinalizeOutcome::Done(reply);
            };
            if accmode == O_WRONLY && (flags & O_NONBLOCK) != 0 {
                let (read_refs, _) = state.pipe_refcounts(pipe).unwrap_or((0, 0));
                if read_refs == 0 {
                    reply.label = TRONA_NOT_CONNECTED;
                    return OpenFinalizeOutcome::Done(reply);
                }
            }
            let Some(fd) = state.alloc_pipe_client_slot(cli_handle, vh, pipe, flags) else {
                reply.label = TRONA_OUT_OF_MEMORY;
                return OpenFinalizeOutcome::Done(reply);
            };

            if accmode != O_RDWR && (flags & O_NONBLOCK) == 0 {
                let (read_refs, write_refs) = state.pipe_refcounts(pipe).unwrap_or((0, 0));
                let ready = if accmode == O_RDONLY {
                    write_refs != 0
                } else {
                    read_refs != 0
                };
                if !ready {
                    crate::fileops::tty_wait::defer_fifo_open(
                        state,
                        cli_handle,
                        fd,
                        pipe,
                        accmode,
                        &raw mut reply,
                    );
                    return OpenFinalizeOutcome::Done(reply);
                }
            }

            reply.label = TRONA_OK;
            reply.length = 1;
            reply.regs[0] = fd as u64;
            return OpenFinalizeOutcome::Done(reply);
        }

        if force_directory || vnode.vtype != VT_REG {
            reply.label = TRONA_NOT_SUPPORTED;
            return OpenFinalizeOutcome::Done(reply);
        }

        let accmode = flags & O_ACCMODE;
        if accmode > O_RDWR {
            reply.label = TRONA_INVALID_ARGUMENT;
            return OpenFinalizeOutcome::Done(reply);
        }
        if (flags & O_TRUNC) != 0 && !truncate_done {
            if accmode == O_RDONLY {
                reply.label = TRONA_INVALID_OPERATION;
                return OpenFinalizeOutcome::Done(reply);
            }
            match crate::vfs_core::vops::truncate(state, vh, 0) {
                Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => {}
                Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                    return OpenFinalizeOutcome::TruncateDeferred(op_id);
                }
                Err(err) => {
                    reply.label = err;
                    return OpenFinalizeOutcome::Done(reply);
                }
            }
        }

        let Some(fd) = state.alloc_client_slot(cli_handle, vh, OBJ_FILE, flags) else {
            reply.label = TRONA_OUT_OF_MEMORY;
            return OpenFinalizeOutcome::Done(reply);
        };
        reply.label = TRONA_OK;
        reply.length = 1;
        reply.regs[0] = fd as u64;
        OpenFinalizeOutcome::Done(reply)
    }
}

unsafe fn open_path_as_slot(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    path_reg: usize,
    force_directory: bool,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, path_reg, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let Some(path_len) = normalize_path_owned(
            state,
            cli_handle,
            path.as_ptr(),
            raw_len,
            abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };

        let flags = if path_reg == 2 {
            (*msg).regs[1] as u32
        } else {
            O_RDONLY
        };
        let mode = if path_reg == 2 {
            (*msg).regs[0] as u32
        } else {
            0
        };
        open_abs_path_as_slot(
            state,
            cli_handle,
            force_directory,
            flags,
            mode,
            &abs_path[..path_len],
            reply,
        );
    }
}

pub(crate) unsafe fn handle_open_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe { open_path_as_slot(state, cli_handle, 2, false, msg, reply) }
}

pub(crate) unsafe fn handle_openat_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let flags = (*msg).regs[1] as u32;
        let mode = (*msg).regs[2] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 3, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let Some(path_len) = normalize_path_at_owned(
            state,
            cli_handle,
            dirfd,
            path.as_ptr(),
            raw_len,
            abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };

        open_abs_path_as_slot(
            state,
            cli_handle,
            false,
            flags,
            mode,
            &abs_path[..path_len],
            reply,
        );
    }
}

pub(crate) unsafe fn handle_close_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        if fd < 0 || !state.release_client_slot(cli_handle, fd as usize) {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        (*reply).label = TRONA_OK;
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_opendir_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe { open_path_as_slot(state, cli_handle, 0, true, msg, reply) }
}

/// Owner-side completion handler for `open`/`openat`/`creat`. Receives
/// `saved` with the resolved vnode in `current_packed` and the
/// per-call args (flags/mode/dirfd/force_directory) in
/// `saved.aux.open`. Runs the sync tail (`open_finalize_with_vnode`)
/// and ships the wire reply via the saved reply slot.
///
/// # Safety
///
/// Owner-thread only.
pub(crate) unsafe fn complete_open_continuation(
    state: &mut VfsState,
    op_id: crate::owner::pending_ops::PendingOpId,
    saved: &crate::owner::namei::NameiResumeState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let _ = completion;
    unsafe {
        let body = saved.aux.open;
        let cli_handle = match crate::owner::pending_ops::get(op_id) {
            Some(op) => crate::owner::dispatch::unpack_client_handle(op.client_handle_raw),
            None => {
                crate::owner::continuation::fail_continuation(op_id, TRONA_INVALID_OPERATION);
                return true;
            }
        };
        let vh = crate::arena::Handle::<crate::vfs_core::vnode::Vnode>::new(
            saved.current_packed as u32,
            (saved.current_packed >> 32) as u32,
        );
        let path_len = (saved.path_len as usize).min(saved.path.len());
        let abs_path = &saved.path[..path_len];
        let force_directory = body.force_directory != 0;
        let mut local_reply = TronaMsg::zeroed();
        let outcome = match body.stage {
            crate::owner::namei::OPEN_STAGE_LOOKUP => {
                // `vh` carries the namei result; an invalid handle
                // means the walk resolved to "not found"
                // (Handle::INVALID sentinel). Re-enter the sync tail
                // so O_CREAT dispatches to STAGE_PARENT_LOOKUP and
                // existing entries flow through `open_finalize_or_defer`.
                let resolved = if vh.is_valid() { Some(vh) } else { None };
                open_continue_after_lookup(
                    state,
                    cli_handle,
                    force_directory,
                    body.flags,
                    body.mode,
                    abs_path,
                    resolved,
                    &raw mut local_reply,
                )
            }
            crate::owner::namei::OPEN_STAGE_PARENT_LOOKUP => {
                // STAGE_PARENT_LOOKUP — `vh` is the parent vnode that
                // `lookup_parent_for_client_deferred` resolved; an
                // invalid handle means the parent chain failed.
                if !vh.is_valid() {
                    crate::owner::continuation::fail_continuation(op_id, TRONA_NOT_FOUND);
                    return true;
                }
                open_continue_after_parent_lookup(
                    state,
                    cli_handle,
                    force_directory,
                    body.flags,
                    body.mode,
                    abs_path,
                    vh,
                    body.leaf_offset,
                    &raw mut local_reply,
                )
            }
            crate::owner::namei::OPEN_STAGE_CREATE => {
                // STAGE_CREATE — `vh` is the freshly created child
                // vnode. Drive the open finalize tail; truncate may
                // still defer onto STAGE_TRUNCATE.
                if !vh.is_valid() {
                    crate::owner::continuation::fail_continuation(op_id, TRONA_INVALID_OPERATION);
                    return true;
                }
                open_finalize_or_defer(
                    state,
                    cli_handle,
                    force_directory,
                    body.flags,
                    body.mode,
                    abs_path,
                    vh,
                    false,
                    &raw mut local_reply,
                )
            }
            crate::owner::namei::OPEN_STAGE_TRUNCATE => {
                // STAGE_TRUNCATE — truncate is done; finish fd
                // allocation by re-entering finalize with
                // `truncate_done=true` so the truncate stage runs at
                // most once.
                if !vh.is_valid() {
                    crate::owner::continuation::fail_continuation(op_id, TRONA_INVALID_OPERATION);
                    return true;
                }
                open_finalize_or_defer(
                    state,
                    cli_handle,
                    force_directory,
                    body.flags,
                    body.mode,
                    abs_path,
                    vh,
                    true,
                    &raw mut local_reply,
                )
            }
            _ => {
                crate::owner::continuation::fail_continuation(op_id, TRONA_INVALID_OPERATION);
                return true;
            }
        };
        match outcome {
            OpenStepOutcome::Done => {
                if local_reply.label != crate::fileops::tty_wait::REPLY_DEFERRED_LABEL {
                    crate::owner::continuation::finish_continuation(op_id, local_reply);
                }
            }
            OpenStepOutcome::DeferredAt(new_op_id, stage, leaf_offset) => {
                // Chained defer mid-completion: cannot reach
                // `save_current_caller` from this context, so transfer
                // the existing reply slot from `op_id` onto `new_op_id`
                // and overwrite only the aux body so the new op carries
                // the matching `OPEN_STAGE_*`.
                let new_body = crate::owner::namei::OpenContBody {
                    flags: body.flags,
                    mode: body.mode,
                    dirfd_packed: body.dirfd_packed,
                    result_fd_hint: body.result_fd_hint,
                    force_directory: body.force_directory,
                    stage,
                    leaf_offset,
                    _pad: [0; 72],
                };
                if !crate::owner::continuation::transition_to_chained_op_with_aux(
                    op_id,
                    new_op_id,
                    crate::owner::pending_ops::PO_KIND_OPEN_CONT,
                    crate::owner::namei::NAMEI_AUX_OPEN,
                    crate::owner::namei::namei_aux_open(new_body),
                ) {
                    crate::owner::continuation::fail_continuation(op_id, TRONA_INVALID_OPERATION);
                }
            }
        }
    }
    true
}
