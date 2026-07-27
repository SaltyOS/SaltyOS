// SPDX-License-Identifier: GPL-2.0-only
//! POSIX shared memory: shm_open and shm_unlink.

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_posix::consts::*;
use trona_protocol::posix::*;
use uapi::*;

use crate::arena::Handle;
use crate::fs::tmpfs::TmpfsVnodeData;
use crate::ipc_ctx;
use crate::owner::VfsState;
use crate::owner::dispatch::{build_namei_ctx, root_vnode_for};
use crate::personality::posix::consts::*;
use crate::personality::posix::types::ShmData;
use crate::server::client::{
    extract_path, flags_append_writes, flags_nonblocking, object_open_flags,
};
use crate::server::consts::*;
use crate::server::types::*;
use crate::vfs_core::cred::VfsCred;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::namei_common::{NAMEI_CREATE, NAMEI_FOLLOW, NAMEI_WANTPARENT, NameiArgs};
use crate::vfs_core::outcome::{Parked, Ready};
use crate::vfs_core::vnode::VnodeHandle;

fn shm_rights_from_flags(flags: u32) -> u8 {
    match flags & O_ACCMODE {
        O_WRONLY => OBJ_RIGHT_WRITE,
        O_RDWR => OBJ_RIGHT_READ | OBJ_RIGHT_WRITE,
        _ => OBJ_RIGHT_READ,
    }
}

unsafe fn normalize_shm_name<'a>(
    path: &'a [u8; MAX_PATH_LEN],
    name_len: u8,
) -> Option<(*const u8, u8)> {
    if name_len <= 1 || path[0] != b'/' {
        return None;
    }
    let component_len = name_len as usize - 1;
    let component_ptr = unsafe { path.as_ptr().add(1) };
    for i in 0..component_len {
        if unsafe { *component_ptr.add(i) } == b'/' {
            return None;
        }
    }
    Some((component_ptr, component_len as u8))
}

unsafe fn build_shm_full_path(
    name_ptr: *const u8,
    component_len: u8,
    out: &mut [u8; MAX_PATH_LEN],
) -> Option<u16> {
    let prefix = b"/tmp/shm/";
    let full_len = prefix.len() + component_len as usize;
    if full_len > MAX_PATH_LEN {
        return None;
    }
    for i in 0..prefix.len() {
        out[i] = prefix[i];
    }
    for i in 0..component_len as usize {
        out[prefix.len() + i] = unsafe { *name_ptr.add(i) };
    }
    Some(full_len as u16)
}

unsafe fn alloc_shm_handle(state: &mut VfsState) -> Option<Handle<ShmData>> {
    let handle = state.shm_data.alloc()?;
    if let Some(shm) = state.shm_data.get_mut(handle) {
        shm.active = 1;
        shm.unlinked = 0;
        shm.num_pages = 0;
    }
    Some(handle)
}

unsafe fn free_shm_handle(state: &mut VfsState, handle: Handle<ShmData>) {
    if !handle.is_valid() {
        return;
    }
    if let Some(shm) = state.shm_data.get_mut(handle) {
        shm.active = 0;
        shm.unlinked = 0;
        shm.num_pages = 0;
    }
    let _ = state.shm_data.release(handle);
}

pub(crate) unsafe fn slot_shm_handle(
    state: &VfsState,
    slot: &crate::server::open_object::OpenObject,
) -> Handle<ShmData> {
    unsafe {
        if slot.kind() != ObjectKind::Shm {
            return Handle::<ShmData>::INVALID;
        }
        let vh = slot.vnode_handle();
        if !vh.is_valid() {
            return Handle::<ShmData>::INVALID;
        }
        let Some(vnode) = state.vnodes.get(vh) else {
            return Handle::<ShmData>::INVALID;
        };
        let vd = vnode.data as *const TmpfsVnodeData;
        if vd.is_null() {
            return Handle::<ShmData>::INVALID;
        }
        (*vd).shm_handle
    }
}

unsafe fn shm_has_live_slots(
    state: &VfsState,
    handle: Handle<ShmData>,
    skip: Option<(ClientHandle, usize)>,
) -> bool {
    // Collect candidate `(client, fd)` pairs first; the
    // `for_each_active` closure borrows `state.clients`, which prevents
    // `state.open_object_at` / `state.shm_data.get` calls inside.
    let mut candidates: [(ClientHandle, usize); MAX_CLIENT_OBJECTS] =
        [(ClientHandle::INVALID, 0); MAX_CLIENT_OBJECTS];
    let mut n = 0usize;
    state.clients.for_each_active(|client_handle, client| {
        for fd in 0..MAX_CLIENT_OBJECTS {
            if let Some((skip_handle, skip_fd)) = skip {
                if client_handle == skip_handle && fd == skip_fd {
                    continue;
                }
            }
            if !client.slots[fd].is_free() && n < candidates.len() {
                candidates[n] = (client_handle, fd);
                n += 1;
            }
        }
        true
    });
    for &(ch, fd) in candidates[..n].iter() {
        let Some(obj) = state.open_object_at(ch, fd) else {
            continue;
        };
        if obj.kind() != ObjectKind::Shm {
            continue;
        }
        if unsafe { slot_shm_handle(state, obj) } == handle {
            return true;
        }
    }
    false
}

pub(crate) unsafe fn destroy_shm_backing(
    state: &mut VfsState,
    handle: Handle<ShmData>,
) -> Result<(), u64> {
    unsafe {
        let num_pages = match state.shm_data.get(handle) {
            Some(shm) => shm.num_pages,
            None => return Ok(()),
        };
        if num_pages == 0 {
            return Ok(());
        }

        let mut mm_msg = TronaMsg::zeroed();
        let mut mm_reply = TronaMsg::zeroed();
        mm_msg.label = MM_SHM_DESTROY;
        mm_msg.length = 1;
        mm_msg.regs[0] = handle.slot() as u64;
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::mmsrv_ep(),
            &raw const mm_msg,
            &raw mut mm_reply,
        );
        if err != 0 {
            return Err(TRONA_INVALID_OPERATION);
        }
        if mm_reply.label != TRONA_OK {
            return Err(mm_reply.label);
        }

        if let Some(shm) = state.shm_data.get_mut(handle) {
            shm.num_pages = 0;
        }
        Ok(())
    }
}

pub(crate) unsafe fn maybe_reclaim_unlinked_shm(
    state: &mut VfsState,
    handle: Handle<ShmData>,
    vnode_handle: VnodeHandle,
    skip: Option<(ClientHandle, usize)>,
) -> Result<(), u64> {
    unsafe {
        let Some(shm) = state.shm_data.get(handle) else {
            return Ok(());
        };
        if shm.unlinked == 0 || shm_has_live_slots(state, handle, skip) {
            return Ok(());
        }

        destroy_shm_backing(state, handle)?;

        if vnode_handle.is_valid() {
            if let Some(vnode) = state.vnodes.get(vnode_handle) {
                let vd = vnode.data as *mut TmpfsVnodeData;
                if !vd.is_null() && (*vd).shm_handle == handle {
                    (*vd).shm_handle = Handle::<ShmData>::INVALID;
                    (*vd).size = 0;
                }
            }
        }

        free_shm_handle(state, handle);
        Ok(())
    }
}

pub(crate) unsafe fn ensure_shm_backing_pages(
    state: &mut VfsState,
    handle: Handle<ShmData>,
    num_pages: u16,
) -> Result<(), u64> {
    unsafe {
        let current_pages = match state.shm_data.get(handle) {
            Some(shm) => shm.num_pages,
            None => return Err(TRONA_INVALID_OPERATION),
        };

        if current_pages == num_pages {
            return Ok(());
        }

        if num_pages == 0 {
            destroy_shm_backing(state, handle)?;
            return Ok(());
        }

        let mut mm_msg = TronaMsg::zeroed();
        let mut mm_reply = TronaMsg::zeroed();
        mm_msg.label = if current_pages == 0 {
            MM_SHM_CREATE
        } else {
            MM_SHM_RESIZE
        };
        mm_msg.length = 2;
        mm_msg.regs[0] = handle.slot() as u64;
        mm_msg.regs[1] = num_pages as u64;
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::mmsrv_ep(),
            &raw const mm_msg,
            &raw mut mm_reply,
        );
        if err != 0 {
            return Err(TRONA_OUT_OF_MEMORY);
        }
        if mm_reply.label != TRONA_OK {
            return Err(mm_reply.label);
        }

        if let Some(shm) = state.shm_data.get_mut(handle) {
            shm.num_pages = num_pages;
        }
        Ok(())
    }
}

unsafe fn ensure_shm_dir(state: &mut VfsState) -> Result<(), u64> {
    unsafe {
        let path = b"/tmp/shm";
        let cred = VfsCred::root();
        let root = root_vnode_for(state, ClientHandle::new(0, 0));

        let mut namei_ctx = build_namei_ctx(state);
        let args = NameiArgs {
            start: root,
            path: path.as_ptr(),
            path_len: path.len() as u16,
            flags: NAMEI_FOLLOW | NAMEI_CREATE | NAMEI_WANTPARENT,
            cred,
            root,
        };

        let ni = match crate::personality::posix::namei::namei_posix(&mut namei_ctx, &args) {
            Ok(ni) => ni,
            Err(e) => {
                return Err(e.to_trona());
            }
        };

        if ni.vp.is_valid() {
            return Ok(());
        }

        if !ni.dvp.is_valid() {
            return Err(TRONA_NOT_FOUND);
        }

        let mut ctx = match crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, ni.dvp) {
            Some(c) => c,
            None => return Err(TRONA_NOT_SUPPORTED),
        };
        let ops = &*(*ctx.vnode).ops;
        let mkdir_result = (ops.meta.mkdir)(
            &mut ctx,
            ni.last_name,
            ni.last_name_len,
            S_IFDIR_L | 0o755,
            &raw const cred,
        );

        match mkdir_result {
            Ok(_) => Ok(()),
            Err(e) => Err(e.to_trona()),
        }
    }
}

pub(crate) unsafe fn handle_shm_open(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let flags = (*msg).regs[0] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let name_len = extract_path(msg, 1, path.as_mut_ptr());
        let Some((name_ptr, component_len)) = normalize_shm_name(&path, name_len) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        };
        let mut full_path = [0u8; MAX_PATH_LEN];
        let Some(full_len) = build_shm_full_path(name_ptr, component_len, &mut full_path) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        };

        if let Err(label) = ensure_shm_dir(state) {
            (*reply).label = label;
            return false;
        }

        // Resolve the full path via namei.
        let cred = VfsCred::root();
        let root = root_vnode_for(state, cli_handle);

        let mut namei_ctx = build_namei_ctx(state);
        let args = NameiArgs {
            start: root,
            path: full_path.as_ptr(),
            path_len: full_len,
            flags: NAMEI_FOLLOW | NAMEI_CREATE | NAMEI_WANTPARENT,
            cred,
            root,
        };

        let ni = match crate::personality::posix::namei::namei_posix(&mut namei_ctx, &args) {
            Ok(ni) => ni,
            Err(e) => {
                (*reply).label = e.to_trona();
                return false;
            }
        };

        // Existing SHM object found.
        if ni.vp.is_valid() {
            let vnode = match state.vnodes.get(ni.vp) {
                Some(v) => v,
                None => {
                    (*reply).label = TRONA_NOT_FOUND;
                    return false;
                }
            };
            let vd = vnode.data as *const TmpfsVnodeData;
            let shm_handle = if vd.is_null() {
                Handle::<ShmData>::INVALID
            } else {
                (*vd).shm_handle
            };
            if !shm_handle.is_valid() || state.shm_data.get(shm_handle).is_none() {
                (*reply).label = TRONA_NOT_FOUND;
                return false;
            }
            if (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL) {
                (*reply).label = TRONA_ALREADY_EXISTS;
                return false;
            }
            let shm_id = shm_handle.slot();

            // Allocate fd.
            let Some(fd) = state.reserve_fd_owned(cli_handle) else {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            };

            if let Some(obj) = state.open_object_at_mut(cli_handle, fd as usize) {
                obj.rights = shm_rights_from_flags(flags);
                obj.flags = object_open_flags(flags);
                obj.append_on_write = if flags_append_writes(flags) { 1 } else { 0 };
                obj.nonblocking = if flags_nonblocking(flags) { 1 } else { 0 };
                obj.offset = 0;
                obj.set_shm(ni.vp, shm_id);
            } else {
                state.slot_release(cli_handle, fd as usize);
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return false;
            }

            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = fd as u64;
            return false;
        }

        // Create new SHM object.
        if (flags & O_CREAT) == 0 {
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        }

        if !ni.dvp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        }

        // Allocate fd.
        let Some(fd) = crate::fileops::open::reserve_fd_owned(state, cli_handle) else {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        };

        let Some(shm_handle) = alloc_shm_handle(state) else {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        };

        // Create the tmpfs file via VopContext.
        let mut ctx = match crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, ni.dvp) {
            Some(c) => c,
            None => {
                free_shm_handle(state, shm_handle);
                (*reply).label = TRONA_NOT_SUPPORTED;
                return false;
            }
        };
        let ops = &*(*ctx.vnode).ops;
        let new_vh = match (ops.meta.create)(
            &mut ctx,
            ni.last_name,
            ni.last_name_len,
            S_IFREG_L | 0o666,
            &raw const cred,
        ) {
            Ok(Ready(vh)) => vh,
            Ok(Parked(_)) => {
                free_shm_handle(state, shm_handle);
                (*reply).label = TRONA_BUSY;
                return false;
            }
            Err(e) => {
                free_shm_handle(state, shm_handle);
                (*reply).label = e.to_trona();
                return false;
            }
        };

        // Bind the arena-backed SHM descriptor to the tmpfs vnode.
        if let Some(vnode) = state.vnodes.get(new_vh) {
            let vd = vnode.data as *mut TmpfsVnodeData;
            if !vd.is_null() {
                (*vd).shm_handle = shm_handle;
            }
        }

        // Fill fd slot.
        if let Some(obj) = state.open_object_at_mut(cli_handle, fd as usize) {
            obj.rights = shm_rights_from_flags(flags);
            obj.flags = object_open_flags(flags);
            obj.append_on_write = if flags_append_writes(flags) { 1 } else { 0 };
            obj.nonblocking = if flags_nonblocking(flags) { 1 } else { 0 };
            obj.offset = 0;
            obj.set_shm(new_vh, shm_handle.slot());
        } else {
            state.slot_release(cli_handle, fd as usize);
            free_shm_handle(state, shm_handle);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = fd as u64;
        false
    }
}

pub(crate) unsafe fn handle_shm_unlink(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let name_len = extract_path(msg, 0, path.as_mut_ptr());
        let Some((name_ptr, component_len)) = normalize_shm_name(&path, name_len) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        };
        let mut full_path = [0u8; MAX_PATH_LEN];
        let Some(full_len) = build_shm_full_path(name_ptr, component_len, &mut full_path) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        };

        // Resolve via namei.
        let cred = VfsCred::root();
        let root = root_vnode_for(state, cli_handle);

        let mut namei_ctx = build_namei_ctx(state);
        let args = NameiArgs {
            start: root,
            path: full_path.as_ptr(),
            path_len: full_len,
            flags: NAMEI_FOLLOW | NAMEI_WANTPARENT,
            cred,
            root,
        };

        let ni = match crate::personality::posix::namei::namei_posix(&mut namei_ctx, &args) {
            Ok(ni) => ni,
            Err(e) => {
                (*reply).label = e.to_trona();
                return false;
            }
        };

        if !ni.dvp.is_valid() || !ni.vp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return false;
        }

        // Verify it's a SHM object.
        let shm_handle = match state.vnodes.get(ni.vp) {
            Some(vnode) => {
                let vd = vnode.data as *const TmpfsVnodeData;
                if vd.is_null() || !(*vd).shm_handle.is_valid() {
                    (*reply).label = TRONA_NOT_FOUND;
                    return false;
                }
                (*vd).shm_handle
            }
            None => {
                (*reply).label = TRONA_NOT_FOUND;
                return false;
            }
        };

        // Unlink via VopContext.
        let mut ctx = match crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, ni.dvp) {
            Some(c) => c,
            None => {
                (*reply).label = TRONA_NOT_SUPPORTED;
                return false;
            }
        };
        let ops = &*(*ctx.vnode).ops;
        match (ops.meta.unlink)(&mut ctx, ni.last_name, ni.last_name_len) {
            Ok(Ready(())) => {
                if let Some(shm) = state.shm_data.get_mut(shm_handle) {
                    shm.unlinked = 1;
                }
                let _ = maybe_reclaim_unlinked_shm(state, shm_handle, ni.vp, None);
                (*reply).label = TRONA_OK;
            }
            Ok(Parked(_)) => {
                (*reply).label = TRONA_BUSY;
            }
            Err(e) => {
                (*reply).label = e.to_trona();
            }
        }

        false
    }
}
