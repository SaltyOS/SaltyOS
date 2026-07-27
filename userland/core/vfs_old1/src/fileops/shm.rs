// SPDX-License-Identifier: GPL-2.0-only
//! POSIX shared memory: `shm_open` and `shm_unlink`.

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_posix::consts::*;
use trona_protocol::posix::*;
use uapi::*;

use crate::owner::VfsState;
use crate::server::client::{MAX_PATH_LEN, extract_path};
use crate::server::types::{ClientHandle, PERS_POSIX};
use crate::vfs_core::vnode::VnodeHandle;
use crate::vfs_core::vops;

fn normalize_shm_name(path: &[u8; MAX_PATH_LEN], name_len: u8) -> Option<(&[u8], usize)> {
    if name_len <= 1 || path[0] != b'/' {
        return None;
    }
    let component = &path[1..name_len as usize];
    if component.is_empty() || component.contains(&b'/') {
        return None;
    }
    Some((component, component.len()))
}

fn build_shm_full_path(name: &[u8], out: &mut [u8; MAX_PATH_LEN]) -> Option<usize> {
    let prefix = b"/tmp/shm/";
    let full_len = prefix.len() + name.len();
    if full_len > out.len() {
        return None;
    }
    out[..prefix.len()].copy_from_slice(prefix);
    out[prefix.len()..full_len].copy_from_slice(name);
    Some(full_len)
}

/// `/tmp/shm` lives inside the tmpfs that covers `/tmp`. Path lookup
/// uses the dynamic vops-aware resolver — bootstrap-only walks would
/// miss every entry created via tmpfs.
fn lookup_shm_path(state: &mut VfsState, path: &[u8]) -> Option<VnodeHandle> {
    match state.lookup_path_dynamic_absolute(path, false) {
        Ok(crate::vfs_core::vops::VfsOpResult::Complete(vh)) => vh,
        _ => None,
    }
}

/// Remove a shm path via the parent's `remove_child` vop. The parent
/// is /tmp (tmpfs root) so the dispatch always lands in tmpfs.
fn remove_shm_path(state: &mut VfsState, path: &[u8]) -> u64 {
    let (parent_slice, name_slice) = match split_parent_and_name(path) {
        Some(pair) => pair,
        None => return TRONA_INVALID_ARGUMENT,
    };
    let parent_buf = match copy_into_buf(parent_slice) {
        Some(buf) => buf,
        None => return TRONA_INVALID_ARGUMENT,
    };
    let parent_vh = match lookup_shm_path(state, &parent_buf[..parent_slice.len()]) {
        Some(vh) => vh,
        None => return TRONA_NOT_FOUND,
    };
    let name_buf = match copy_into_buf(name_slice) {
        Some(buf) => buf,
        None => return TRONA_INVALID_ARGUMENT,
    };
    crate::vfs_core::vops::label_from_unit_result(vops::remove_child(
        state,
        parent_vh,
        &name_buf[..name_slice.len()],
        false,
        PERS_POSIX,
    ))
}

fn split_parent_and_name(path: &[u8]) -> Option<(&[u8], &[u8])> {
    let last_slash = path.iter().rposition(|&b| b == b'/')?;
    let parent = if last_slash == 0 {
        b"/".as_slice()
    } else {
        &path[..last_slash]
    };
    let name = &path[last_slash + 1..];
    if name.is_empty() {
        return None;
    }
    Some((parent, name))
}

fn copy_into_buf(src: &[u8]) -> Option<[u8; MAX_PATH_LEN]> {
    if src.len() > MAX_PATH_LEN {
        return None;
    }
    let mut buf = [0u8; MAX_PATH_LEN];
    buf[..src.len()].copy_from_slice(src);
    Some(buf)
}

/// Create `/tmp/shm` (idempotent) inside the tmpfs covering `/tmp`,
/// stamping the sticky-bit + 0777 mode POSIX requires for shm storage.
///
/// The `set_mode` only fires on creation — re-stamping every call
/// breaks `shm_open(O_RDONLY)` after the parent mount is remounted
/// read-only. An existing dir with the wrong mode is silently
/// honored; admins fix that with `chmod`, not implicitly via
/// `shm_open`.
fn ensure_shm_dir(state: &mut VfsState) -> u64 {
    let parent = match lookup_shm_path(state, b"/tmp") {
        Some(vh) => vh,
        None => return TRONA_NOT_FOUND,
    };
    match vops::lookup_child(state, parent, b"shm") {
        Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(_))) => return TRONA_OK,
        Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {}
        Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
            // SHM bootstrap helper has no continuation slot; reclaim
            // the op so the worker-side state is not orphaned.
            unsafe {
                crate::owner::pending_ops::free(op_id);
            }
            return TRONA_NOT_SUPPORTED;
        }
        Err(_) => {}
    }
    let mode = (S_IFDIR as u32) | 0o1777;
    let dir_vh = match vops::mkdir_child(state, parent, b"shm", mode, PERS_POSIX) {
        Ok(crate::vfs_core::vops::VfsOpResult::Complete(vh)) => vh,
        Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
            // SHM open has no dedicated `PO_KIND_*_CONT` variant, so a
            // backend-deferred mkdir on /tmp/shm cannot be adopted into
            // a syscall continuation. Reclaim the op explicitly and
            // surface the limit to the caller instead of dropping
            // `op_id` and orphaning the worker-side state.
            unsafe {
                crate::owner::pending_ops::free(op_id);
            }
            return TRONA_NOT_SUPPORTED;
        }
        Err(err) => return err,
    };
    crate::vfs_core::vops::label_from_unit_result(vops::set_mode(state, dir_vh, mode))
}

pub(crate) unsafe fn handle_shm_open_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let flags = (*msg).regs[0] as u32;
        let allowed = O_ACCMODE | O_CREAT | O_EXCL | O_CLOEXEC | O_NONBLOCK | O_TRUNC;
        if (flags & !allowed) != 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let mut path = [0u8; MAX_PATH_LEN];
        let name_len = extract_path(msg, 1, path.as_mut_ptr());
        let Some((name, _)) = normalize_shm_name(&path, name_len) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };

        let ensure = ensure_shm_dir(state);
        if ensure != TRONA_OK {
            (*reply).label = ensure;
            (*reply).length = 0;
            return;
        }

        let mut full_path = [0u8; MAX_PATH_LEN];
        let Some(full_len) = build_shm_full_path(name, &mut full_path) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let full_path = &full_path[..full_len];

        if let Some(vh) = lookup_shm_path(state, full_path) {
            let Some(shm) = state.shm_by_vnode(vh) else {
                (*reply).label = TRONA_NOT_FOUND;
                (*reply).length = 0;
                return;
            };
            if (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL) {
                (*reply).label = TRONA_ALREADY_EXISTS;
                (*reply).length = 0;
                return;
            }
            if (flags & O_TRUNC) != 0 {
                let mut mm_msg = TronaMsg::zeroed();
                let mut mm_reply = TronaMsg::zeroed();
                let shm_id = match state.shm_state(shm) {
                    Some(s) => s.id,
                    None => {
                        (*reply).label = TRONA_NOT_FOUND;
                        (*reply).length = 0;
                        return;
                    }
                };
                mm_msg.label = MM_SHM_RESIZE;
                mm_msg.length = 2;
                mm_msg.regs[0] = shm_id;
                mm_msg.regs[1] = 0;
                let err = ipc::call_ctx(
                    crate::ipc_ctx(),
                    trona_runtime::client::caps::mmsrv_ep(),
                    &raw const mm_msg,
                    &raw mut mm_reply,
                );
                if err != 0
                    || (mm_reply.label != TRONA_OK && mm_reply.label != TRONA_INVALID_ARGUMENT)
                {
                    (*reply).label = if err != 0 {
                        TRONA_INVALID_OPERATION
                    } else {
                        mm_reply.label
                    };
                    (*reply).length = 0;
                    return;
                }
                if let Some(vn) = state.vnodes.get_mut(vh) {
                    vn.size = 0;
                    vn.mtime_ns = vn.mtime_ns.saturating_add(1);
                }
                if let Some(shm_state) = state.shm_state_mut(shm) {
                    shm_state.num_pages = 0;
                }
            }
            let Some(fd) = state.alloc_shm_client_slot(cli_handle, vh, shm, flags) else {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                (*reply).length = 0;
                return;
            };
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = fd as u64;
            return;
        }

        if (flags & O_CREAT) == 0 {
            (*reply).label = TRONA_NOT_FOUND;
            (*reply).length = 0;
            return;
        }

        let parent = match lookup_shm_path(state, b"/tmp/shm") {
            Some(vh) => vh,
            None => {
                (*reply).label = TRONA_NOT_FOUND;
                (*reply).length = 0;
                return;
            }
        };
        let vh = match vops::create_regular_child(
            state,
            parent,
            name,
            (S_IFREG as u32) | 0o666,
            PERS_POSIX,
        ) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(vh)) => vh,
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                // SHM open has no dedicated `PO_KIND_*_CONT` variant
                // for backend-deferred file creation today. Reclaim
                // the op rather than dropping `op_id` and orphaning
                // the worker-side state; the caller sees an explicit
                // `TRONA_NOT_SUPPORTED` instead of a silent hang.
                unsafe {
                    crate::owner::pending_ops::free(op_id);
                }
                (*reply).label = TRONA_NOT_SUPPORTED;
                (*reply).length = 0;
                return;
            }
            Err(err) => {
                (*reply).label = err;
                (*reply).length = 0;
                return;
            }
        };
        let Some(shm) = state.alloc_shm_state(vh) else {
            let _ = remove_shm_path(state, full_path);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return;
        };
        let Some(fd) = state.alloc_shm_client_slot(cli_handle, vh, shm, flags) else {
            let _ = state.shms.release(shm);
            let _ = remove_shm_path(state, full_path);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return;
        };
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = fd as u64;
    }
}

pub(crate) unsafe fn handle_shm_unlink_owned(
    state: &mut VfsState,
    _cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let name_len = extract_path(msg, 0, path.as_mut_ptr());
        let Some((name, _)) = normalize_shm_name(&path, name_len) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let mut full_path = [0u8; MAX_PATH_LEN];
        let Some(full_len) = build_shm_full_path(name, &mut full_path) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let full_path = &full_path[..full_len];
        let Some(vh) = lookup_shm_path(state, full_path) else {
            (*reply).label = TRONA_NOT_FOUND;
            (*reply).length = 0;
            return;
        };
        let Some(shm) = state.shm_by_vnode(vh) else {
            (*reply).label = TRONA_NOT_FOUND;
            (*reply).length = 0;
            return;
        };
        let unlink_result = remove_shm_path(state, full_path);
        if unlink_result != TRONA_OK {
            (*reply).label = unlink_result;
            (*reply).length = 0;
            return;
        }

        let (open_refs, shm_id) = match state.shm_state_mut(shm) {
            Some(shm_state) => {
                shm_state.unlinked = 1;
                (shm_state.open_refs, shm_state.id)
            }
            None => {
                (*reply).label = TRONA_NOT_FOUND;
                (*reply).length = 0;
                return;
            }
        };
        if open_refs == 0 {
            let mut mm_msg = TronaMsg::zeroed();
            let mut mm_reply = TronaMsg::zeroed();
            mm_msg.label = MM_SHM_DESTROY;
            mm_msg.length = 1;
            mm_msg.regs[0] = shm_id;
            let _ = ipc::call_ctx(
                crate::ipc_ctx(),
                trona_runtime::client::caps::mmsrv_ep(),
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            let _ = state.shms.release(shm);
            state.reclaim_bootstrap_vnode(vh);
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 0;
    }
}

/// Backend RPC completion routing for mmsrv shm ops.
///
/// Returns `true` only when this dispatcher has shipped the saved
/// reply. Returns `false` so the cascade falls through to the default
/// arm; per-op routing for `BACKEND_OP_MMSRV_SHM_*` (create / destroy /
/// map / unmap / resize) lands here.
pub(crate) unsafe fn complete_shm_op(
    _state: &mut VfsState,
    _completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    false
}
