// SPDX-License-Identifier: GPL-2.0-only
//! Synchronous bootstrap tree mutation helpers.

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use uapi::*;

use crate::owner::VfsState;
use crate::server::client::{
    MAX_PATH_LEN, extract_path, normalize_path_at_owned, normalize_path_owned,
};
use crate::server::types::ClientHandle;

const INLINE_TARGET_MAX: usize = 64;
const MUTATE_STAGE_INITIAL: u32 = 0;
const MUTATE_STAGE_HAVE_SOURCE: u32 = 1;

fn leaf_offset_of(abs_path: &[u8]) -> usize {
    abs_path
        .iter()
        .rposition(|&b| b == b'/')
        .map(|p| p + 1)
        .unwrap_or(0)
}

unsafe fn finish_label(op_id: crate::owner::pending_ops::PendingOpId, label: u64) {
    unsafe {
        let mut reply = TronaMsg::zeroed();
        reply.label = label;
        crate::owner::continuation::finish_continuation(op_id, reply);
    }
}

unsafe fn transition_or_fail(
    old_op_id: crate::owner::pending_ops::PendingOpId,
    new_op_id: crate::owner::pending_ops::PendingOpId,
    new_kind: crate::owner::pending_ops::PendingOpKind,
    aux_kind: u8,
    aux: crate::owner::namei::NameiResumeAux,
) {
    unsafe {
        if !crate::owner::continuation::transition_to_chained_op_with_aux(
            old_op_id, new_op_id, new_kind, aux_kind, aux,
        ) {
            crate::owner::continuation::fail_continuation(old_op_id, TRONA_INVALID_OPERATION);
        }
    }
}

unsafe fn transition_or_fail_with_stage(
    old_op_id: crate::owner::pending_ops::PendingOpId,
    new_op_id: crate::owner::pending_ops::PendingOpId,
    new_kind: crate::owner::pending_ops::PendingOpKind,
    aux_kind: u8,
    aux: crate::owner::namei::NameiResumeAux,
    stage: u32,
    scratch_idx: usize,
    scratch_value: u64,
) {
    set_op_stage_and_scratch(new_op_id, stage, scratch_idx, scratch_value);
    unsafe {
        transition_or_fail(old_op_id, new_op_id, new_kind, aux_kind, aux);
    }
}

fn unpack_saved_vnode(
    saved: &crate::owner::namei::NameiResumeState,
) -> Option<crate::vfs_core::vnode::VnodeHandle> {
    if saved.current_packed == u32::MAX as u64 {
        return None;
    }
    Some(crate::arena::Handle::<crate::vfs_core::vnode::Vnode>::new(
        saved.current_packed as u32,
        (saved.current_packed >> 32) as u32,
    ))
}

fn pack_vnode(vnode: crate::vfs_core::vnode::VnodeHandle) -> u64 {
    ((vnode.epoch() as u64) << 32) | vnode.slot() as u64
}

fn client_handle_for_op(op_id: crate::owner::pending_ops::PendingOpId) -> ClientHandle {
    unsafe {
        crate::owner::pending_ops::unpack_client_handle(
            crate::owner::pending_ops::get(op_id)
                .map(|op| op.client_handle_raw)
                .unwrap_or(0),
        )
    }
}

fn op_stage(op_id: crate::owner::pending_ops::PendingOpId) -> u32 {
    unsafe {
        crate::owner::pending_ops::get(op_id)
            .map(|op| op.stage)
            .unwrap_or(MUTATE_STAGE_INITIAL)
    }
}

fn op_scratch(op_id: crate::owner::pending_ops::PendingOpId, idx: usize) -> u64 {
    unsafe {
        crate::owner::pending_ops::get(op_id)
            .map(|op| op.scratch[idx])
            .unwrap_or(0)
    }
}

fn set_op_stage_and_scratch(
    op_id: crate::owner::pending_ops::PendingOpId,
    stage: u32,
    scratch_idx: usize,
    scratch_value: u64,
) {
    unsafe {
        if let Some(op) = crate::owner::pending_ops::get_mut(op_id) {
            op.stage = stage;
            op.scratch[scratch_idx] = scratch_value;
        }
    }
}

unsafe fn extract_packed_paths(
    msg: *const TronaMsg,
    reg_offset: usize,
    first_len: usize,
    second_len: usize,
    first: &mut [u8; MAX_PATH_LEN],
    second: &mut [u8; MAX_PATH_LEN],
) {
    unsafe {
        let raw = &(*msg).regs[reg_offset] as *const u64 as *const u8;
        for idx in 0..first_len {
            first[idx] = *raw.add(idx);
        }
        let second_off = ((first_len + 7) / 8) * 8;
        for idx in 0..second_len {
            second[idx] = *raw.add(second_off + idx);
        }
    }
}

unsafe fn adopt_mkdir_continuation(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    op_id: crate::owner::pending_ops::PendingOpId,
    abs_path: &[u8],
    mode: u32,
    reply: *mut TronaMsg,
) {
    let body = crate::owner::namei::MkdirContBody {
        mode,
        _pad: [0; 92],
    };
    let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
    let ok = unsafe {
        crate::owner::continuation::adopt_deferred_op_for_continuation(
            op_id,
            crate::owner::pending_ops::PO_KIND_MKDIR_CONT,
            badge,
            cli_handle,
            reply,
            abs_path,
            crate::owner::namei::NAMEI_AUX_MKDIR,
            crate::owner::namei::namei_aux_mkdir(body),
        )
    };
    if !ok {
        unsafe {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
        }
    }
}

unsafe fn adopt_unlink_continuation(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    op_id: crate::owner::pending_ops::PendingOpId,
    abs_path: &[u8],
    remove_dir: bool,
    reply: *mut TronaMsg,
) {
    let body = crate::owner::namei::UnlinkContBody {
        flags: if remove_dir { AT_REMOVEDIR as u32 } else { 0 },
        _pad: [0; 92],
    };
    let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
    let ok = unsafe {
        crate::owner::continuation::adopt_deferred_op_for_continuation(
            op_id,
            crate::owner::pending_ops::PO_KIND_UNLINK_CONT,
            badge,
            cli_handle,
            reply,
            abs_path,
            crate::owner::namei::NAMEI_AUX_UNLINK,
            crate::owner::namei::namei_aux_unlink(body),
        )
    };
    if !ok {
        unsafe {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
        }
    }
}

unsafe fn adopt_symlink_continuation(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    op_id: crate::owner::pending_ops::PendingOpId,
    abs_path: &[u8],
    target: &[u8],
    reply: *mut TronaMsg,
) {
    let mut body = crate::owner::namei::SymlinkContBody {
        target_len: target.len() as u8,
        _pad: [0; 7],
        target: [0; crate::owner::namei::SYMLINK_TARGET_INLINE_MAX],
        _reserved: [0; 24],
    };
    body.target[..target.len()].copy_from_slice(target);
    let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
    let ok = unsafe {
        crate::owner::continuation::adopt_deferred_op_for_continuation(
            op_id,
            crate::owner::pending_ops::PO_KIND_SYMLINK_CONT,
            badge,
            cli_handle,
            reply,
            abs_path,
            crate::owner::namei::NAMEI_AUX_SYMLINK,
            crate::owner::namei::namei_aux_symlink(body),
        )
    };
    if !ok {
        unsafe {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
        }
    }
}

unsafe fn adopt_rename_continuation(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    op_id: crate::owner::pending_ops::PendingOpId,
    old_abs: &[u8],
    new_abs: &[u8],
    stage: u32,
    old_parent_packed: u64,
    reply: *mut TronaMsg,
) {
    if new_abs.len() > crate::owner::namei::RENAME_NEW_PATH_MAX {
        unsafe {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
        }
        return;
    }
    let mut body = crate::owner::namei::RenameContBody {
        new_path_len: new_abs.len() as u8,
        _pad: [0; 7],
        new_path: [0; crate::owner::namei::RENAME_NEW_PATH_MAX],
    };
    body.new_path[..new_abs.len()].copy_from_slice(new_abs);
    let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
    set_op_stage_and_scratch(op_id, stage, 1, old_parent_packed);
    let ok = unsafe {
        crate::owner::continuation::adopt_deferred_op_for_continuation(
            op_id,
            crate::owner::pending_ops::PO_KIND_RENAME_CONT,
            badge,
            cli_handle,
            reply,
            old_abs,
            crate::owner::namei::NAMEI_AUX_RENAME,
            crate::owner::namei::namei_aux_rename(body),
        )
    };
    if !ok {
        unsafe {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
        }
    }
}

unsafe fn adopt_link_continuation(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    op_id: crate::owner::pending_ops::PendingOpId,
    old_abs: &[u8],
    new_abs: &[u8],
    stage: u32,
    source_packed: u64,
    reply: *mut TronaMsg,
) {
    if new_abs.len() > crate::owner::namei::LINK_NEW_PATH_MAX {
        unsafe {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
        }
        return;
    }
    let mut body = crate::owner::namei::LinkContBody {
        new_path_len: new_abs.len() as u8,
        _pad: [0; 7],
        new_path: [0; crate::owner::namei::LINK_NEW_PATH_MAX],
    };
    body.new_path[..new_abs.len()].copy_from_slice(new_abs);
    let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
    set_op_stage_and_scratch(op_id, stage, 1, source_packed);
    let ok = unsafe {
        crate::owner::continuation::adopt_deferred_op_for_continuation(
            op_id,
            crate::owner::pending_ops::PO_KIND_LINK_CONT,
            badge,
            cli_handle,
            reply,
            old_abs,
            crate::owner::namei::NAMEI_AUX_LINK,
            crate::owner::namei::namei_aux_link(body),
        )
    };
    if !ok {
        unsafe {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
        }
    }
}

unsafe fn populate_direct_deferred(
    state: &VfsState,
    cli_handle: ClientHandle,
    op_id: crate::owner::pending_ops::PendingOpId,
    reply: *mut TronaMsg,
) {
    unsafe {
        if !crate::owner::continuation::populate_alloced_op_for_caller(
            state, op_id, cli_handle, reply,
        ) {
            crate::owner::pending_ops::free(op_id);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
        }
    }
}

unsafe fn finish_rename_with_parents(
    state: &mut VfsState,
    op_id: crate::owner::pending_ops::PendingOpId,
    body: crate::owner::namei::RenameContBody,
    old_parent: crate::vfs_core::vnode::VnodeHandle,
    new_parent: crate::vfs_core::vnode::VnodeHandle,
    old_abs: &[u8],
    new_abs: &[u8],
) {
    unsafe {
        let old_leaf = leaf_offset_of(old_abs);
        let new_leaf = leaf_offset_of(new_abs);
        let cli_handle = client_handle_for_op(op_id);
        match crate::vfs_core::vops::rename_child(
            state,
            old_parent,
            &old_abs[old_leaf..],
            new_parent,
            &new_abs[new_leaf..],
            state.client_personality(cli_handle),
        ) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => finish_label(op_id, TRONA_OK),
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(new_op_id)) => {
                transition_or_fail(
                    op_id,
                    new_op_id,
                    crate::owner::pending_ops::PO_KIND_RENAME_CONT,
                    crate::owner::namei::NAMEI_AUX_RENAME,
                    crate::owner::namei::namei_aux_rename(body),
                );
            }
            Err(err) => finish_label(op_id, err),
        }
    }
}

unsafe fn finish_link_with_parent(
    state: &mut VfsState,
    op_id: crate::owner::pending_ops::PendingOpId,
    body: crate::owner::namei::LinkContBody,
    source: crate::vfs_core::vnode::VnodeHandle,
    parent: crate::vfs_core::vnode::VnodeHandle,
    new_abs: &[u8],
) {
    unsafe {
        let leaf = leaf_offset_of(new_abs);
        let cli_handle = client_handle_for_op(op_id);
        match crate::vfs_core::vops::link_vnode_into(
            state,
            source,
            parent,
            &new_abs[leaf..],
            state.client_personality(cli_handle),
        ) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => finish_label(op_id, TRONA_OK),
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(new_op_id)) => {
                transition_or_fail(
                    op_id,
                    new_op_id,
                    crate::owner::pending_ops::PO_KIND_LINK_CONT,
                    crate::owner::namei::NAMEI_AUX_LINK,
                    crate::owner::namei::namei_aux_link(body),
                );
            }
            Err(err) => finish_label(op_id, err),
        }
    }
}

pub(crate) unsafe fn handle_mkdir_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mode = (*msg).regs[0] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 1, path.as_mut_ptr());
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

        let create_mode = (S_IFDIR as u32) | (mode & 0o7777);
        match state.lookup_parent_for_client_deferred(cli_handle, &abs_path[..path_len]) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(parent_lookup))) => {
                match crate::vfs_core::vops::mkdir_child(
                    state,
                    parent_lookup.parent.handle,
                    &abs_path[parent_lookup.leaf_offset..path_len],
                    create_mode,
                    state.client_personality(cli_handle),
                ) {
                    Ok(crate::vfs_core::vops::VfsOpResult::Complete(_)) => {
                        (*reply).label = TRONA_OK
                    }
                    Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                        adopt_mkdir_continuation(
                            state,
                            cli_handle,
                            op_id,
                            &abs_path[..path_len],
                            create_mode,
                            reply,
                        );
                    }
                    Err(err) => (*reply).label = err,
                }
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                (*reply).label = TRONA_NOT_FOUND;
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                adopt_mkdir_continuation(
                    state,
                    cli_handle,
                    op_id,
                    &abs_path[..path_len],
                    create_mode,
                    reply,
                );
            }
            Err(err) => (*reply).label = err,
        }
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_mkdirat_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mode = (*msg).regs[1] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 2, path.as_mut_ptr());
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

        let create_mode = (S_IFDIR as u32) | (mode & 0o7777);
        match state.lookup_parent_for_client_deferred(cli_handle, &abs_path[..path_len]) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(parent_lookup))) => {
                match crate::vfs_core::vops::mkdir_child(
                    state,
                    parent_lookup.parent.handle,
                    &abs_path[parent_lookup.leaf_offset..path_len],
                    create_mode,
                    state.client_personality(cli_handle),
                ) {
                    Ok(crate::vfs_core::vops::VfsOpResult::Complete(_)) => {
                        (*reply).label = TRONA_OK
                    }
                    Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                        adopt_mkdir_continuation(
                            state,
                            cli_handle,
                            op_id,
                            &abs_path[..path_len],
                            create_mode,
                            reply,
                        );
                    }
                    Err(err) => (*reply).label = err,
                }
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                (*reply).label = TRONA_NOT_FOUND;
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                adopt_mkdir_continuation(
                    state,
                    cli_handle,
                    op_id,
                    &abs_path[..path_len],
                    create_mode,
                    reply,
                );
            }
            Err(err) => (*reply).label = err,
        }
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_unlink_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 0, path.as_mut_ptr());
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

        match state.lookup_parent_for_client_deferred(cli_handle, &abs_path[..path_len]) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(parent_lookup))) => {
                match crate::vfs_core::vops::remove_child(
                    state,
                    parent_lookup.parent.handle,
                    &abs_path[parent_lookup.leaf_offset..path_len],
                    false,
                    state.client_personality(cli_handle),
                ) {
                    Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => {
                        (*reply).label = TRONA_OK
                    }
                    Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                        adopt_unlink_continuation(
                            state,
                            cli_handle,
                            op_id,
                            &abs_path[..path_len],
                            false,
                            reply,
                        );
                    }
                    Err(err) => (*reply).label = err,
                }
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                (*reply).label = TRONA_NOT_FOUND
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                adopt_unlink_continuation(
                    state,
                    cli_handle,
                    op_id,
                    &abs_path[..path_len],
                    false,
                    reply,
                );
            }
            Err(err) => (*reply).label = err,
        }
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_unlinkat_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let at_flags = (*msg).regs[1] as i32;
        if (at_flags & !AT_REMOVEDIR) != 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 2, path.as_mut_ptr());
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

        let remove_dir = (at_flags & AT_REMOVEDIR) != 0;
        match state.lookup_parent_for_client_deferred(cli_handle, &abs_path[..path_len]) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(parent_lookup))) => {
                match crate::vfs_core::vops::remove_child(
                    state,
                    parent_lookup.parent.handle,
                    &abs_path[parent_lookup.leaf_offset..path_len],
                    remove_dir,
                    state.client_personality(cli_handle),
                ) {
                    Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => {
                        (*reply).label = TRONA_OK
                    }
                    Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                        adopt_unlink_continuation(
                            state,
                            cli_handle,
                            op_id,
                            &abs_path[..path_len],
                            remove_dir,
                            reply,
                        );
                    }
                    Err(err) => (*reply).label = err,
                }
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                (*reply).label = TRONA_NOT_FOUND
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                adopt_unlink_continuation(
                    state,
                    cli_handle,
                    op_id,
                    &abs_path[..path_len],
                    remove_dir,
                    reply,
                );
            }
            Err(err) => (*reply).label = err,
        }
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_rmdir_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 0, path.as_mut_ptr());
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

        match state.lookup_parent_for_client_deferred(cli_handle, &abs_path[..path_len]) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(parent_lookup))) => {
                match crate::vfs_core::vops::remove_child(
                    state,
                    parent_lookup.parent.handle,
                    &abs_path[parent_lookup.leaf_offset..path_len],
                    true,
                    state.client_personality(cli_handle),
                ) {
                    Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => {
                        (*reply).label = TRONA_OK
                    }
                    Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                        adopt_unlink_continuation(
                            state,
                            cli_handle,
                            op_id,
                            &abs_path[..path_len],
                            true,
                            reply,
                        );
                    }
                    Err(err) => (*reply).label = err,
                }
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                (*reply).label = TRONA_NOT_FOUND
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                adopt_unlink_continuation(
                    state,
                    cli_handle,
                    op_id,
                    &abs_path[..path_len],
                    true,
                    reply,
                );
            }
            Err(err) => (*reply).label = err,
        }
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_symlinkat_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let target_len = core::cmp::min((*msg).regs[0] as usize, INLINE_TARGET_MAX);
        let dirfd = (*msg).regs[1] as i32;
        let link_len = core::cmp::min((*msg).regs[2] as usize, MAX_PATH_LEN);
        if target_len == 0 || link_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let mut link_path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let link_src = &(*msg).regs[3] as *const u64 as *const u8;
        for idx in 0..link_len {
            link_path[idx] = *link_src.add(idx);
        }
        let Some(path_len) = normalize_path_at_owned(
            state,
            cli_handle,
            dirfd,
            link_path.as_ptr(),
            link_len as u8,
            abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };

        let link_regs = (link_len + 7) / 8;
        let target_src = (&(*msg).regs[3 + link_regs]) as *const u64 as *const u8;
        let mut target = [0u8; INLINE_TARGET_MAX];
        for idx in 0..target_len {
            target[idx] = *target_src.add(idx);
        }

        match state.lookup_parent_for_client_deferred(cli_handle, &abs_path[..path_len]) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(parent_lookup))) => {
                match crate::vfs_core::vops::symlink_child(
                    state,
                    parent_lookup.parent.handle,
                    &abs_path[parent_lookup.leaf_offset..path_len],
                    &target[..target_len],
                    state.client_personality(cli_handle),
                ) {
                    Ok(crate::vfs_core::vops::VfsOpResult::Complete(_)) => {
                        (*reply).label = TRONA_OK
                    }
                    Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                        adopt_symlink_continuation(
                            state,
                            cli_handle,
                            op_id,
                            &abs_path[..path_len],
                            &target[..target_len],
                            reply,
                        );
                    }
                    Err(err) => (*reply).label = err,
                }
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                (*reply).label = TRONA_NOT_FOUND
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                adopt_symlink_continuation(
                    state,
                    cli_handle,
                    op_id,
                    &abs_path[..path_len],
                    &target[..target_len],
                    reply,
                );
            }
            Err(err) => (*reply).label = err,
        }
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_mkfifo_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mode = (*msg).regs[0] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 1, path.as_mut_ptr());
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

        (*reply).label = match state.bootstrap_create_fifo_path_for_personality(
            &abs_path[..path_len],
            (S_IFIFO as u32) | (mode & 0o7777),
            state.client_personality(cli_handle),
        ) {
            Ok(_) => TRONA_OK,
            Err(err) => err,
        };
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_rename_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let old_len = core::cmp::min((*msg).regs[0] as usize, MAX_PATH_LEN);
        let new_len = core::cmp::min((*msg).regs[1] as usize, MAX_PATH_LEN);
        if old_len == 0 || new_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let mut old_path = [0u8; MAX_PATH_LEN];
        let mut new_path = [0u8; MAX_PATH_LEN];
        let mut old_abs = [0u8; MAX_PATH_LEN];
        let mut new_abs = [0u8; MAX_PATH_LEN];
        extract_packed_paths(msg, 2, old_len, new_len, &mut old_path, &mut new_path);

        let Some(old_abs_len) = normalize_path_owned(
            state,
            cli_handle,
            old_path.as_ptr(),
            old_len as u8,
            old_abs.as_mut_ptr(),
        ) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let Some(new_abs_len) = normalize_path_owned(
            state,
            cli_handle,
            new_path.as_ptr(),
            new_len as u8,
            new_abs.as_mut_ptr(),
        ) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };

        if new_abs_len > crate::owner::namei::RENAME_NEW_PATH_MAX {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        match state.lookup_parent_for_client_deferred(cli_handle, &old_abs[..old_abs_len]) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(old_parent))) => {
                match state.lookup_parent_for_client_deferred(cli_handle, &new_abs[..new_abs_len]) {
                    Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(new_parent))) => {
                        match crate::vfs_core::vops::rename_child(
                            state,
                            old_parent.parent.handle,
                            &old_abs[old_parent.leaf_offset..old_abs_len],
                            new_parent.parent.handle,
                            &new_abs[new_parent.leaf_offset..new_abs_len],
                            state.client_personality(cli_handle),
                        ) {
                            Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => {
                                (*reply).label = TRONA_OK
                            }
                            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                                populate_direct_deferred(state, cli_handle, op_id, reply);
                            }
                            Err(err) => (*reply).label = err,
                        }
                    }
                    Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                        (*reply).label = TRONA_NOT_FOUND;
                    }
                    Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                        adopt_rename_continuation(
                            state,
                            cli_handle,
                            op_id,
                            &old_abs[..old_abs_len],
                            &new_abs[..new_abs_len],
                            MUTATE_STAGE_HAVE_SOURCE,
                            pack_vnode(old_parent.parent.handle),
                            reply,
                        );
                    }
                    Err(err) => (*reply).label = err,
                }
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                (*reply).label = TRONA_NOT_FOUND;
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                adopt_rename_continuation(
                    state,
                    cli_handle,
                    op_id,
                    &old_abs[..old_abs_len],
                    &new_abs[..new_abs_len],
                    MUTATE_STAGE_INITIAL,
                    0,
                    reply,
                );
            }
            Err(err) => (*reply).label = err,
        }
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_renameat_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let old_dirfd = (*msg).regs[0] as i32;
        let new_dirfd = (*msg).regs[1] as i32;
        let old_len = core::cmp::min((*msg).regs[2] as usize, MAX_PATH_LEN);
        let new_len = core::cmp::min((*msg).regs[3] as usize, MAX_PATH_LEN);
        if old_len == 0 || new_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let mut old_path = [0u8; MAX_PATH_LEN];
        let mut new_path = [0u8; MAX_PATH_LEN];
        let mut old_abs = [0u8; MAX_PATH_LEN];
        let mut new_abs = [0u8; MAX_PATH_LEN];
        extract_packed_paths(msg, 4, old_len, new_len, &mut old_path, &mut new_path);

        let Some(old_abs_len) = normalize_path_at_owned(
            state,
            cli_handle,
            old_dirfd,
            old_path.as_ptr(),
            old_len as u8,
            old_abs.as_mut_ptr(),
        ) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let Some(new_abs_len) = normalize_path_at_owned(
            state,
            cli_handle,
            new_dirfd,
            new_path.as_ptr(),
            new_len as u8,
            new_abs.as_mut_ptr(),
        ) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };

        if new_abs_len > crate::owner::namei::RENAME_NEW_PATH_MAX {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        match state.lookup_parent_for_client_deferred(cli_handle, &old_abs[..old_abs_len]) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(old_parent))) => {
                match state.lookup_parent_for_client_deferred(cli_handle, &new_abs[..new_abs_len]) {
                    Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(new_parent))) => {
                        match crate::vfs_core::vops::rename_child(
                            state,
                            old_parent.parent.handle,
                            &old_abs[old_parent.leaf_offset..old_abs_len],
                            new_parent.parent.handle,
                            &new_abs[new_parent.leaf_offset..new_abs_len],
                            state.client_personality(cli_handle),
                        ) {
                            Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => {
                                (*reply).label = TRONA_OK
                            }
                            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                                populate_direct_deferred(state, cli_handle, op_id, reply);
                            }
                            Err(err) => (*reply).label = err,
                        }
                    }
                    Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                        (*reply).label = TRONA_NOT_FOUND;
                    }
                    Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                        adopt_rename_continuation(
                            state,
                            cli_handle,
                            op_id,
                            &old_abs[..old_abs_len],
                            &new_abs[..new_abs_len],
                            MUTATE_STAGE_HAVE_SOURCE,
                            pack_vnode(old_parent.parent.handle),
                            reply,
                        );
                    }
                    Err(err) => (*reply).label = err,
                }
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                (*reply).label = TRONA_NOT_FOUND;
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                adopt_rename_continuation(
                    state,
                    cli_handle,
                    op_id,
                    &old_abs[..old_abs_len],
                    &new_abs[..new_abs_len],
                    MUTATE_STAGE_INITIAL,
                    0,
                    reply,
                );
            }
            Err(err) => (*reply).label = err,
        }
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_linkat_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let old_dirfd = (*msg).regs[0] as i32;
        let new_dirfd = (*msg).regs[1] as i32;
        let at_flags = (*msg).regs[2] as i32;
        let old_len = core::cmp::min((*msg).regs[3] as usize, MAX_PATH_LEN);
        let new_len = core::cmp::min((*msg).regs[4] as usize, MAX_PATH_LEN);
        if old_len == 0 || new_len == 0 || (at_flags & !AT_SYMLINK_FOLLOW) != 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let mut old_path = [0u8; MAX_PATH_LEN];
        let mut new_path = [0u8; MAX_PATH_LEN];
        let mut old_abs = [0u8; MAX_PATH_LEN];
        let mut new_abs = [0u8; MAX_PATH_LEN];
        extract_packed_paths(msg, 5, old_len, new_len, &mut old_path, &mut new_path);

        let Some(old_abs_len) = normalize_path_at_owned(
            state,
            cli_handle,
            old_dirfd,
            old_path.as_ptr(),
            old_len as u8,
            old_abs.as_mut_ptr(),
        ) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };
        let Some(new_abs_len) = normalize_path_at_owned(
            state,
            cli_handle,
            new_dirfd,
            new_path.as_ptr(),
            new_len as u8,
            new_abs.as_mut_ptr(),
        ) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        };

        if new_abs_len > crate::owner::namei::LINK_NEW_PATH_MAX {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        match state.lookup_path_dynamic_for_client(
            cli_handle,
            &old_abs[..old_abs_len],
            (at_flags & AT_SYMLINK_FOLLOW) == 0,
        ) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(source))) => {
                match state.lookup_parent_for_client_deferred(cli_handle, &new_abs[..new_abs_len]) {
                    Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(parent_lookup))) => {
                        match crate::vfs_core::vops::link_vnode_into(
                            state,
                            source,
                            parent_lookup.parent.handle,
                            &new_abs[parent_lookup.leaf_offset..new_abs_len],
                            state.client_personality(cli_handle),
                        ) {
                            Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => {
                                (*reply).label = TRONA_OK
                            }
                            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                                populate_direct_deferred(state, cli_handle, op_id, reply);
                            }
                            Err(err) => (*reply).label = err,
                        }
                    }
                    Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                        (*reply).label = TRONA_NOT_FOUND;
                    }
                    Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                        adopt_link_continuation(
                            state,
                            cli_handle,
                            op_id,
                            &old_abs[..old_abs_len],
                            &new_abs[..new_abs_len],
                            MUTATE_STAGE_HAVE_SOURCE,
                            pack_vnode(source),
                            reply,
                        );
                    }
                    Err(err) => (*reply).label = err,
                }
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                (*reply).label = TRONA_NOT_FOUND;
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(op_id)) => {
                adopt_link_continuation(
                    state,
                    cli_handle,
                    op_id,
                    &old_abs[..old_abs_len],
                    &new_abs[..new_abs_len],
                    MUTATE_STAGE_INITIAL,
                    0,
                    reply,
                );
            }
            Err(err) => (*reply).label = err,
        }
        (*reply).length = 0;
    }
}

/// Path-syscall continuation routing for `unlink` / `unlinkat` /
/// `rmdir`. Path resolution and the saltyfs `remove_child` deferral
/// land here once the saltyfs vertical slice wires the deferred RPC.
pub(crate) unsafe fn complete_unlink_continuation(
    state: &mut VfsState,
    op_id: crate::owner::pending_ops::PendingOpId,
    saved: &crate::owner::namei::NameiResumeState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let _ = completion;
    unsafe {
        let body = saved.aux.unlink;
        let Some(parent_vh) = unpack_saved_vnode(saved) else {
            finish_label(op_id, TRONA_NOT_FOUND);
            return true;
        };
        let path_len = (saved.path_len as usize).min(saved.path.len());
        let leaf = leaf_offset_of(&saved.path[..path_len]);
        let remove_dir = (body.flags & AT_REMOVEDIR as u32) != 0;
        match crate::vfs_core::vops::remove_child(
            state,
            parent_vh,
            &saved.path[leaf..path_len],
            remove_dir,
            state.client_personality(crate::owner::pending_ops::unpack_client_handle(
                crate::owner::pending_ops::get(op_id)
                    .map(|op| op.client_handle_raw)
                    .unwrap_or(0),
            )),
        ) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(())) => finish_label(op_id, TRONA_OK),
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(new_op_id)) => transition_or_fail(
                op_id,
                new_op_id,
                crate::owner::pending_ops::PO_KIND_UNLINK_CONT,
                crate::owner::namei::NAMEI_AUX_UNLINK,
                crate::owner::namei::namei_aux_unlink(body),
            ),
            Err(err) => finish_label(op_id, err),
        }
    }
    true
}

/// Path-syscall continuation routing for `mkdir` / `mkdirat`. Lands
/// here once the saltyfs vertical slice wires the deferred
/// `mkdir_child` RPC.
pub(crate) unsafe fn complete_mkdir_continuation(
    state: &mut VfsState,
    op_id: crate::owner::pending_ops::PendingOpId,
    saved: &crate::owner::namei::NameiResumeState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let _ = completion;
    unsafe {
        let body = saved.aux.mkdir;
        let Some(parent_vh) = unpack_saved_vnode(saved) else {
            finish_label(op_id, TRONA_NOT_FOUND);
            return true;
        };
        let path_len = (saved.path_len as usize).min(saved.path.len());
        let leaf = leaf_offset_of(&saved.path[..path_len]);
        match crate::vfs_core::vops::mkdir_child(
            state,
            parent_vh,
            &saved.path[leaf..path_len],
            body.mode,
            state.client_personality(crate::owner::pending_ops::unpack_client_handle(
                crate::owner::pending_ops::get(op_id)
                    .map(|op| op.client_handle_raw)
                    .unwrap_or(0),
            )),
        ) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(_)) => finish_label(op_id, TRONA_OK),
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(new_op_id)) => transition_or_fail(
                op_id,
                new_op_id,
                crate::owner::pending_ops::PO_KIND_MKDIR_CONT,
                crate::owner::namei::NAMEI_AUX_MKDIR,
                crate::owner::namei::namei_aux_mkdir(body),
            ),
            Err(err) => finish_label(op_id, err),
        }
    }
    true
}

/// Path-syscall continuation routing for `rename` / `renameat`. Lands
/// here once the saltyfs vertical slice wires the deferred
/// `rename_child` RPC across the two-path walk.
pub(crate) unsafe fn complete_rename_continuation(
    state: &mut VfsState,
    op_id: crate::owner::pending_ops::PendingOpId,
    saved: &crate::owner::namei::NameiResumeState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let _ = completion;
    unsafe {
        let body = saved.aux.rename;
        let new_len = (body.new_path_len as usize).min(body.new_path.len());
        let new_abs = &body.new_path[..new_len];
        let old_path_len = (saved.path_len as usize).min(saved.path.len());
        let old_abs = &saved.path[..old_path_len];
        let Some(current_vh) = unpack_saved_vnode(saved) else {
            finish_label(op_id, TRONA_NOT_FOUND);
            return true;
        };
        if op_stage(op_id) == MUTATE_STAGE_HAVE_SOURCE {
            let old_parent = crate::arena::Handle::<crate::vfs_core::vnode::Vnode>::new(
                op_scratch(op_id, 1) as u32,
                (op_scratch(op_id, 1) >> 32) as u32,
            );
            finish_rename_with_parents(
                state, op_id, body, old_parent, current_vh, old_abs, new_abs,
            );
            return true;
        }

        let old_parent = current_vh;
        match state.lookup_parent_for_client_deferred(client_handle_for_op(op_id), new_abs) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(new_parent))) => {
                finish_rename_with_parents(
                    state,
                    op_id,
                    body,
                    old_parent,
                    new_parent.parent.handle,
                    old_abs,
                    new_abs,
                );
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                finish_label(op_id, TRONA_NOT_FOUND);
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(new_op_id)) => {
                transition_or_fail_with_stage(
                    op_id,
                    new_op_id,
                    crate::owner::pending_ops::PO_KIND_RENAME_CONT,
                    crate::owner::namei::NAMEI_AUX_RENAME,
                    crate::owner::namei::namei_aux_rename(body),
                    MUTATE_STAGE_HAVE_SOURCE,
                    1,
                    pack_vnode(old_parent),
                );
            }
            Err(err) => finish_label(op_id, err),
        }
    }
    true
}

/// Path-syscall continuation routing for `symlinkat`. Lands here once
/// the saltyfs vertical slice wires the deferred `symlink_child` RPC.
pub(crate) unsafe fn complete_symlink_continuation(
    state: &mut VfsState,
    op_id: crate::owner::pending_ops::PendingOpId,
    saved: &crate::owner::namei::NameiResumeState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let _ = completion;
    unsafe {
        let body = saved.aux.symlink;
        let Some(parent_vh) = unpack_saved_vnode(saved) else {
            finish_label(op_id, TRONA_NOT_FOUND);
            return true;
        };
        let path_len = (saved.path_len as usize).min(saved.path.len());
        let leaf = leaf_offset_of(&saved.path[..path_len]);
        let target_len = (body.target_len as usize).min(body.target.len());
        match crate::vfs_core::vops::symlink_child(
            state,
            parent_vh,
            &saved.path[leaf..path_len],
            &body.target[..target_len],
            state.client_personality(client_handle_for_op(op_id)),
        ) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(_)) => finish_label(op_id, TRONA_OK),
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(new_op_id)) => transition_or_fail(
                op_id,
                new_op_id,
                crate::owner::pending_ops::PO_KIND_SYMLINK_CONT,
                crate::owner::namei::NAMEI_AUX_SYMLINK,
                crate::owner::namei::namei_aux_symlink(body),
            ),
            Err(err) => finish_label(op_id, err),
        }
    }
    true
}

/// Path-syscall continuation routing for `linkat`. Lands here once
/// the saltyfs vertical slice wires the deferred `link_vnode_into`
/// RPC across the two-path walk.
pub(crate) unsafe fn complete_link_continuation(
    state: &mut VfsState,
    op_id: crate::owner::pending_ops::PendingOpId,
    saved: &crate::owner::namei::NameiResumeState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let _ = completion;
    unsafe {
        let body = saved.aux.link;
        let new_len = (body.new_path_len as usize).min(body.new_path.len());
        let new_abs = &body.new_path[..new_len];
        let Some(current_vh) = unpack_saved_vnode(saved) else {
            finish_label(op_id, TRONA_NOT_FOUND);
            return true;
        };
        if op_stage(op_id) == MUTATE_STAGE_HAVE_SOURCE {
            let source = crate::arena::Handle::<crate::vfs_core::vnode::Vnode>::new(
                op_scratch(op_id, 1) as u32,
                (op_scratch(op_id, 1) >> 32) as u32,
            );
            finish_link_with_parent(state, op_id, body, source, current_vh, new_abs);
            return true;
        }

        let source = current_vh;
        match state.lookup_parent_for_client_deferred(client_handle_for_op(op_id), new_abs) {
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(Some(parent_lookup))) => {
                finish_link_with_parent(
                    state,
                    op_id,
                    body,
                    source,
                    parent_lookup.parent.handle,
                    new_abs,
                );
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Complete(None)) => {
                finish_label(op_id, TRONA_NOT_FOUND);
            }
            Ok(crate::vfs_core::vops::VfsOpResult::Deferred(new_op_id)) => {
                transition_or_fail_with_stage(
                    op_id,
                    new_op_id,
                    crate::owner::pending_ops::PO_KIND_LINK_CONT,
                    crate::owner::namei::NAMEI_AUX_LINK,
                    crate::owner::namei::namei_aux_link(body),
                    MUTATE_STAGE_HAVE_SOURCE,
                    1,
                    pack_vnode(source),
                );
            }
            Err(err) => finish_label(op_id, err),
        }
    }
    true
}
