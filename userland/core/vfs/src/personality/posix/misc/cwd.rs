// SPDX-License-Identifier: GPL-2.0-only
//! chdir and getcwd handlers.

use trona::consts::kernel::*;
use trona::types::core::*;

use crate::owner::VfsState;
use crate::owner::dispatch::{build_namei_ctx, client_cred, root_vnode_for, cwd_vnode_for};
use crate::server::client::extract_path;
use crate::server::consts::*;
use crate::server::types::*;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::namei_common::{NameiArgs, NAMEI_DIRECTORY, NAMEI_FOLLOW};
use crate::vfs_core::vnode::VT_DIR;

pub(crate) unsafe fn handle_chdir(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 0, path.as_mut_ptr());
        if path_len == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let cred = client_cred(state, cli_handle);
        let ns_root = root_vnode_for(state, cli_handle);
        let start = cwd_vnode_for(state, cli_handle);

        let namei_ctx = build_namei_ctx(state);
        let args = NameiArgs {
            start,
            path: path.as_ptr(),
            path_len: path_len as u16,
            flags: NAMEI_FOLLOW | NAMEI_DIRECTORY,
            cred,
            root: ns_root,
        };

        let ni = match crate::personality::posix::namei::namei_posix(&namei_ctx, &args) {
            Ok(ni) => ni,
            Err(e) => {
                mount_ctl::clear_trampolines();
                (*reply).label = e.to_trona();
                return;
            }
        };
        mount_ctl::clear_trampolines();

        if !ni.vp.is_valid() {
            (*reply).label = TRONA_NOT_FOUND;
            return;
        }

        let vh = ni.vp;
        let vnode = match state.vnodes.get(vh) {
            Some(v) => v,
            None => { (*reply).label = TRONA_NOT_FOUND; return; }
        };
        if vnode.vtype != VT_DIR {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        // Update client's cwd vnode handle and path string.
        let cli = match state.clients.get_mut(cli_handle) {
            Some(c) => c,
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
        };
        cli.cwd_vnode = vh;

        // Store path string for getcwd.
        let (src_ptr, src_len) = if path[0] == b'/' {
            (path.as_ptr(), path_len as usize)
        } else {
            let mut cwd_len: usize = 0;
            while cwd_len < 128 && cli.cwd[cwd_len] != 0 {
                cwd_len += 1;
            }
            if cwd_len == 0 {
                cwd_len = 1;
                cli.cwd[0] = b'/';
            }
            static mut SCRATCH: [u8; 256] = [0; 256];
            let scratch = &raw mut SCRATCH;
            let mut pos = 0usize;
            for i in 0..cwd_len {
                if pos < 255 {
                    (*scratch)[pos] = cli.cwd[i];
                    pos += 1;
                }
            }
            if pos > 0 && (*scratch)[pos - 1] != b'/' && pos < 255 {
                (*scratch)[pos] = b'/';
                pos += 1;
            }
            for i in 0..path_len as usize {
                if pos < 255 {
                    (*scratch)[pos] = path[i];
                    pos += 1;
                }
            }
            ((*scratch).as_ptr(), pos)
        };

        let copy_len = if src_len < 127 { src_len } else { 127 };
        let mut i = 0;
        while i < copy_len {
            cli.cwd[i] = *src_ptr.add(i);
            i += 1;
        }
        while i < 128 {
            cli.cwd[i] = 0;
            i += 1;
        }

        (*reply).label = TRONA_OK;
    }
}

pub(crate) unsafe fn handle_getcwd(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let max_size = (*msg).regs[0] as usize;

        let cli = match state.clients.get_mut(cli_handle) {
            Some(c) => c,
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
        };

        let mut cwd_len: usize = 0;
        while cwd_len < 128 && cli.cwd[cwd_len] != 0 {
            cwd_len += 1;
        }
        if cwd_len == 0 {
            cwd_len = 1;
            cli.cwd[0] = b'/';
            cli.cwd[1] = 0;
        }

        if max_size == 0 || cwd_len + 1 > max_size {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        (*reply).label = TRONA_OK;
        (*reply).regs[0] = cwd_len as u64;
        let dst = &mut (*reply).regs[1] as *mut u64 as *mut u8;
        let mut i = 0;
        while i < cwd_len {
            *dst.add(i) = cli.cwd[i];
            i += 1;
        }
        (*reply).length = 1 + ((cwd_len as u64 + 7) / 8);
    }
}
