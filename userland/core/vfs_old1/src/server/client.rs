// SPDX-License-Identifier: GPL-2.0-only
//! Client-path helpers.

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use uapi::*;

use crate::owner::VfsState;
use crate::server::types::{ClientHandle, OBJ_DIRECTORY, PERS_WIN32};

pub(crate) const MAX_PATH_LEN: usize = 128;

fn client_cwd_base_path(
    state: &VfsState,
    cli_handle: ClientHandle,
    out: &mut [u8; MAX_PATH_LEN],
) -> Option<usize> {
    let client = state.clients.get(cli_handle)?;
    let base_anchor = if client.cwd_anchor.is_valid() {
        Some(client.cwd_anchor)
    } else {
        state.root_vnode().and_then(|vh| state.anchor_for_vnode(vh))
    }?;
    state.render_anchor_path(base_anchor, out)
}

pub(crate) unsafe fn extract_path(msg: *const TronaMsg, reg_offset: usize, path: *mut u8) -> u8 {
    unsafe {
        let mut path_len = (*msg).regs[reg_offset] as u8;
        if (path_len as usize) > MAX_PATH_LEN {
            path_len = MAX_PATH_LEN as u8;
        }
        let raw = &(*msg).regs[reg_offset + 1] as *const u64 as *const u8;
        for i in 0..path_len as usize {
            *path.add(i) = *raw.add(i);
        }
        path_len
    }
}

pub(crate) unsafe fn normalize_path_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    in_path: *const u8,
    in_len: u8,
    tmp_abs: *mut u8,
) -> Option<usize> {
    unsafe {
        if in_len == 0 {
            return None;
        }

        if state
            .clients
            .get(cli_handle)
            .map(|client| client.personality == PERS_WIN32)
            .unwrap_or(false)
        {
            return crate::personality::win32::path::normalize_path_owned(
                state, cli_handle, in_path, in_len, tmp_abs,
            )
            .ok();
        }

        let mut raw_abs = [0u8; MAX_PATH_LEN];
        let raw_len: usize;

        if *in_path == b'/' {
            raw_len = in_len as usize;
            if raw_len > MAX_PATH_LEN {
                return None;
            }
            for i in 0..raw_len {
                raw_abs[i] = *in_path.add(i);
            }
        } else {
            let mut base = [0u8; MAX_PATH_LEN];
            let cwd_len = client_cwd_base_path(state, cli_handle, &mut base)?;
            let cwd_is_root = cwd_len == 1 && base[0] == b'/';
            let rel_len = in_len as usize;
            raw_len = if cwd_is_root {
                1 + rel_len
            } else {
                cwd_len + 1 + rel_len
            };
            if raw_len > MAX_PATH_LEN {
                return None;
            }

            if cwd_is_root {
                raw_abs[0] = b'/';
                for i in 0..rel_len {
                    raw_abs[1 + i] = *in_path.add(i);
                }
            } else {
                for i in 0..cwd_len {
                    raw_abs[i] = base[i];
                }
                raw_abs[cwd_len] = b'/';
                for i in 0..rel_len {
                    raw_abs[cwd_len + 1 + i] = *in_path.add(i);
                }
            }
        }

        let mut out_len = 1usize;
        *tmp_abs = b'/';
        let mut comp_starts = [0usize; MAX_PATH_LEN / 2];
        let mut depth = 0usize;

        let mut pos = 0usize;
        if raw_len > 0 && raw_abs[0] == b'/' {
            pos = 1;
        }

        while pos < raw_len {
            while pos < raw_len && raw_abs[pos] == b'/' {
                pos += 1;
            }
            if pos >= raw_len {
                break;
            }

            let start = pos;
            while pos < raw_len && raw_abs[pos] != b'/' {
                pos += 1;
            }
            let seg_len = pos - start;
            if seg_len == 0 {
                continue;
            }

            if seg_len == 1 && raw_abs[start] == b'.' {
                continue;
            }
            if seg_len == 2 && raw_abs[start] == b'.' && raw_abs[start + 1] == b'.' {
                if depth > 0 {
                    depth -= 1;
                    out_len = comp_starts[depth];
                    if out_len == 0 {
                        out_len = 1;
                        *tmp_abs = b'/';
                    }
                }
                continue;
            }

            comp_starts[depth] = out_len;
            depth += 1;
            if out_len > 1 {
                *tmp_abs.add(out_len) = b'/';
                out_len += 1;
            }
            if out_len + seg_len > MAX_PATH_LEN {
                return None;
            }
            for i in 0..seg_len {
                *tmp_abs.add(out_len + i) = raw_abs[start + i];
            }
            out_len += seg_len;
        }

        if out_len == 0 {
            *tmp_abs = b'/';
            out_len = 1;
        }

        Some(out_len)
    }
}

pub(crate) unsafe fn normalize_path_at_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    dirfd: i32,
    in_path: *const u8,
    in_len: u8,
    tmp_abs: *mut u8,
) -> Option<usize> {
    unsafe {
        if in_len == 0 {
            return None;
        }
        let is_win32 = state
            .clients
            .get(cli_handle)
            .map(|client| client.personality == PERS_WIN32)
            .unwrap_or(false);
        if is_win32 {
            if dirfd == AT_FDCWD
                || crate::personality::win32::path::uses_explicit_root_or_drive(in_path, in_len)
            {
                return normalize_path_owned(state, cli_handle, in_path, in_len, tmp_abs);
            }
            if dirfd < 0 {
                return None;
            }

            let slot = state.client_open_file(cli_handle, dirfd as usize)?;
            if slot.kind != OBJ_DIRECTORY {
                return None;
            }

            let mut base = [0u8; MAX_PATH_LEN];
            let base_anchor = state.anchor_for_vnode(slot.vnode)?;
            let base_len = state.render_anchor_path(base_anchor, &mut base)?;
            return crate::personality::win32::path::normalize_path_from_base_owned(
                &base[..base_len],
                in_path,
                in_len,
                tmp_abs,
            )
            .ok();
        }
        if *in_path == b'/' || dirfd == AT_FDCWD {
            return normalize_path_owned(state, cli_handle, in_path, in_len, tmp_abs);
        }
        if dirfd < 0 {
            return None;
        }

        let slot = state.client_open_file(cli_handle, dirfd as usize)?;
        if slot.kind != OBJ_DIRECTORY {
            return None;
        }

        let mut base = [0u8; MAX_PATH_LEN];
        let base_anchor = state.anchor_for_vnode(slot.vnode)?;
        let base_len = state.render_anchor_path(base_anchor, &mut base)?;
        let mut raw_abs = [0u8; MAX_PATH_LEN];
        let cwd_is_root = base_len == 1 && base[0] == b'/';
        let rel_len = in_len as usize;
        let raw_len = if cwd_is_root {
            1 + rel_len
        } else {
            base_len + 1 + rel_len
        };
        if raw_len > MAX_PATH_LEN {
            return None;
        }

        if cwd_is_root {
            raw_abs[0] = b'/';
            for i in 0..rel_len {
                raw_abs[1 + i] = *in_path.add(i);
            }
        } else {
            for i in 0..base_len {
                raw_abs[i] = base[i];
            }
            raw_abs[base_len] = b'/';
            for i in 0..rel_len {
                raw_abs[base_len + 1 + i] = *in_path.add(i);
            }
        }

        let mut out_len = 1usize;
        *tmp_abs = b'/';
        let mut comp_starts = [0usize; MAX_PATH_LEN / 2];
        let mut depth = 0usize;
        let mut pos = if raw_len > 0 && raw_abs[0] == b'/' {
            1
        } else {
            0
        };

        while pos < raw_len {
            while pos < raw_len && raw_abs[pos] == b'/' {
                pos += 1;
            }
            if pos >= raw_len {
                break;
            }

            let start = pos;
            while pos < raw_len && raw_abs[pos] != b'/' {
                pos += 1;
            }
            let seg_len = pos - start;
            if seg_len == 0 {
                continue;
            }

            if seg_len == 1 && raw_abs[start] == b'.' {
                continue;
            }
            if seg_len == 2 && raw_abs[start] == b'.' && raw_abs[start + 1] == b'.' {
                if depth > 0 {
                    depth -= 1;
                    out_len = comp_starts[depth];
                    if out_len == 0 {
                        out_len = 1;
                        *tmp_abs = b'/';
                    }
                }
                continue;
            }

            comp_starts[depth] = out_len;
            depth += 1;
            if out_len > 1 {
                *tmp_abs.add(out_len) = b'/';
                out_len += 1;
            }
            if out_len + seg_len > MAX_PATH_LEN {
                return None;
            }
            for i in 0..seg_len {
                *tmp_abs.add(out_len + i) = raw_abs[start + i];
            }
            out_len += seg_len;
        }

        if out_len == 0 {
            *tmp_abs = b'/';
            out_len = 1;
        }
        Some(out_len)
    }
}

pub(crate) unsafe fn write_inline_path_reply(
    reply: *mut TronaMsg,
    path: *const u8,
    path_len: usize,
) {
    unsafe {
        (*reply).label = TRONA_OK;
        (*reply).regs[0] = path_len as u64;
        let dst = &raw mut (*reply).regs[1] as *mut u8;
        for i in 0..path_len {
            *dst.add(i) = *path.add(i);
        }
        (*reply).length = 1 + ((path_len as u64 + 7) / 8);
    }
}
