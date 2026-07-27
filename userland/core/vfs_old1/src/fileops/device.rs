// SPDX-License-Identifier: GPL-2.0-only
//! Character-device open and I/O helpers.

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_posix::consts::*;
use trona_protocol::posix::init::*;
use trona_protocol::posix::server::*;
use uapi::*;

use crate::owner::VfsState;
use crate::server::types::{ClientHandle, OBJ_DEVICE};
use crate::vfs_core::device::{
    DN_CONSOLE, DN_FB0, DN_NULL, DN_PTMX, DN_PTY_SLAVE, DN_TTY_ALIAS, DN_URANDOM, DN_ZERO,
    decode_device_inode,
};

const INLINE_DEVICE_READ_MAX: usize = 152;
const INLINE_DEVICE_WRITE_MAX: usize = 144;
const INLINE_PTY_WRITE_CHUNK: u64 = 136;

const PTY_SIDE_SLAVE: u64 = 0;
const PTY_SIDE_MASTER: u64 = 1;

#[inline]
pub(crate) fn is_device_namespace_path(path: &[u8]) -> bool {
    path == b"/dev" || path.starts_with(b"/dev/")
}

fn device_fd_view(
    state: &VfsState,
    cli_handle: ClientHandle,
    fd: usize,
) -> Option<(u8, u32, u32, u32, crate::vfs_core::vnode::VnodeHandle)> {
    let of = state.client_open_file(cli_handle, fd)?;
    if of.kind != OBJ_DEVICE || !of.vnode.is_valid() {
        return None;
    }
    Some((
        of.device_dev_type,
        of.device_pty_id,
        of.device_generation,
        of.status_flags,
        of.vnode,
    ))
}

fn init_call1(label: u64, arg0: u64, out0: *mut u64) -> bool {
    let mut msg = TronaMsg::zeroed();
    let mut reply = TronaMsg::zeroed();
    msg.label = label;
    msg.length = 1;
    msg.regs[0] = arg0;
    let err = unsafe {
        ipc::call_ctx(
            crate::ipc_ctx(),
            trona_runtime::client::caps::init_ep(),
            &raw const msg,
            &raw mut reply,
        )
    };
    if err != 0 || reply.label != TRONA_OK {
        return false;
    }
    if !out0.is_null() {
        unsafe {
            *out0 = reply.regs[0];
        }
    }
    true
}

fn init_call3(label: u64, arg0: u64, arg1: u64, arg2: u64) -> bool {
    let mut msg = TronaMsg::zeroed();
    let mut reply = TronaMsg::zeroed();
    msg.label = label;
    msg.length = 3;
    msg.regs[0] = arg0;
    msg.regs[1] = arg1;
    msg.regs[2] = arg2;
    let err = unsafe {
        ipc::call_ctx(
            crate::ipc_ctx(),
            trona_runtime::client::caps::init_ep(),
            &raw const msg,
            &raw mut reply,
        )
    };
    err == 0 && reply.label == TRONA_OK
}

fn resolve_controlling_tty(state: &VfsState, cli_handle: ClientHandle) -> Option<(u8, u32, u32)> {
    let badge = state.clients.get(cli_handle)?.badge;
    let mut tty_dev = 0u64;
    if !init_call1(INIT_GET_SESSION_TTY_BADGE, badge, &raw mut tty_dev) {
        return None;
    }
    if tty_dev == TTY_DEV_CONSOLE {
        return Some((DEV_CONSOLE, 0, 0));
    }
    if tty_dev >= TTY_DEV_PTS_BASE {
        let pty_id = tty_dev - TTY_DEV_PTS_BASE;
        if pty_id <= u32::MAX as u64 {
            let generation = state.lookup_live_pty_generation(pty_id as u32)?;
            return Some((DEV_PTY_SLAVE, pty_id as u32, generation));
        }
    }
    None
}

fn tty_dev_id_for_runtime(dev_type: u8, pty_id: u32) -> u64 {
    if dev_type == DEV_CONSOLE {
        tty_dev_for_console()
    } else {
        tty_dev_for_pts(pty_id as u64)
    }
}

fn ttysrv_ioctl(
    pty_id: u32,
    request: u64,
    arg: u64,
    caller_sid: u64,
    caller_pgid: u64,
    reply: *mut TronaMsg,
) {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = POSIX_TTYSRV_PTY_IOCTL;
        req.length = 5;
        req.regs[0] = pty_id as u64;
        req.regs[1] = request;
        req.regs[2] = arg;
        req.regs[3] = caller_sid;
        req.regs[4] = caller_pgid;
        let err = ipc::call_ctx(
            crate::ipc_ctx(),
            crate::posix_ttysrv_ep(),
            &raw const req,
            &raw mut resp,
        );
        if err != 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }
        (*reply).label = resp.label;
        (*reply).length = resp.length;
        for idx in 0..resp.length as usize {
            (*reply).regs[idx] = resp.regs[idx];
        }
    }
}

fn pty_poll(pty_id: u32, dev_type: u8, events: i16) -> i16 {
    if crate::posix_ttysrv_ep() == 0 {
        return POLLERR;
    }

    let mut req = TronaMsg::zeroed();
    let mut resp = TronaMsg::zeroed();
    req.label = POSIX_TTYSRV_PTY_POLL;
    req.length = 3;
    req.regs[0] = pty_id as u64;
    req.regs[1] = events as u16 as u64;
    req.regs[2] = if dev_type == DEV_PTMX {
        PTY_SIDE_MASTER
    } else {
        PTY_SIDE_SLAVE
    };
    let err = unsafe {
        ipc::call_ctx(
            crate::ipc_ctx(),
            crate::posix_ttysrv_ep(),
            &raw const req,
            &raw mut resp,
        )
    };
    if err != 0 || resp.label != TRONA_OK {
        POLLERR
    } else {
        resp.regs[0] as i16
    }
}

unsafe fn open_pty_slave(pty_id: u32, generation: u32) -> u64 {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = POSIX_TTYSRV_PTY_OPEN_SLAVE;
        req.length = 2;
        req.regs[0] = pty_id as u64;
        req.regs[1] = generation as u64;
        let err = ipc::call_ctx(
            crate::ipc_ctx(),
            crate::posix_ttysrv_ep(),
            &raw const req,
            &raw mut resp,
        );
        if err != 0 {
            TRONA_INVALID_OPERATION
        } else {
            resp.label
        }
    }
}

unsafe fn alloc_ptmx() -> Result<u32, u64> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = POSIX_TTYSRV_PTY_ALLOC;
        let err = ipc::call_ctx(
            crate::ipc_ctx(),
            crate::posix_ttysrv_ep(),
            &raw const req,
            &raw mut resp,
        );
        if err != 0 {
            Err(TRONA_INVALID_OPERATION)
        } else if resp.label != TRONA_OK {
            Err(resp.label)
        } else {
            Ok(resp.regs[0] as u32)
        }
    }
}

unsafe fn close_pty_side(pty_id: u32, dev_type: u8) {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = POSIX_TTYSRV_PTY_CLOSE;
        req.length = 2;
        req.regs[0] = pty_id as u64;
        req.regs[1] = if dev_type == DEV_PTMX {
            PTY_SIDE_MASTER
        } else {
            PTY_SIDE_SLAVE
        };
        let _ = ipc::call_ctx(
            crate::ipc_ctx(),
            crate::posix_ttysrv_ep(),
            &raw const req,
            &raw mut reply,
        );
    }
}

unsafe fn fill_zero_read_reply(count: usize, reply: *mut TronaMsg) {
    unsafe {
        (*reply).label = TRONA_OK;
        (*reply).regs[0] = count as u64;
        (*reply).length = 1 + ((count as u64 + 7) / 8);
        let dst = &raw mut (*reply).regs[1] as *mut u8;
        core::ptr::write_bytes(dst, 0, count);
    }
}

unsafe fn fill_urandom_read_reply(count: usize, reply: *mut TronaMsg) {
    unsafe {
        (*reply).label = TRONA_OK;
        (*reply).regs[0] = count as u64;
        (*reply).length = 1 + ((count as u64 + 7) / 8);
        let dst = &raw mut (*reply).regs[1] as *mut u8;
        let mut offset = 0usize;
        while offset < count {
            let word = trona_kernel::syscall::sys_getrandom().unwrap_or(offset as u64);
            let bytes = word.to_le_bytes();
            let chunk = core::cmp::min(8, count - offset);
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst.add(offset), chunk);
            offset += chunk;
        }
    }
}

unsafe fn console_write(msg: *const TronaMsg, count: usize, reply: *mut TronaMsg) {
    unsafe {
        let src = &raw const (*msg).regs[2] as *const u8;
        let mut sent = 0usize;
        while sent < count {
            let chunk = core::cmp::min(24, count - sent);
            let mut req = TronaMsg::zeroed();
            let mut resp = TronaMsg::zeroed();
            req.label = CONSOLE_WRITE;
            req.length = 1 + ((chunk as u64 + 7) / 8);
            req.regs[0] = chunk as u64;
            let dst = &raw mut req.regs[1] as *mut u8;
            core::ptr::copy_nonoverlapping(src.add(sent), dst, chunk);
            let err = ipc::call_ctx(
                crate::ipc_ctx(),
                trona_runtime::client::caps::console_ep(),
                &raw const req,
                &raw mut resp,
            );
            if err != 0 || resp.label != TRONA_OK {
                break;
            }
            sent += chunk;
        }
        (*reply).label = if sent > 0 || count == 0 {
            TRONA_OK
        } else {
            TRONA_INVALID_OPERATION
        };
        (*reply).length = 1;
        (*reply).regs[0] = sent as u64;
    }
}

unsafe fn pty_write(
    msg: *const TronaMsg,
    pty_id: u32,
    dev_type: u8,
    count: usize,
    reply: *mut TronaMsg,
) {
    unsafe {
        let src = &raw const (*msg).regs[2] as *const u8;
        let label = if dev_type == DEV_PTMX {
            POSIX_TTYSRV_PTY_MASTER_WRITE
        } else {
            POSIX_TTYSRV_PTY_WRITE
        };
        let mut sent = 0u64;
        while sent < count as u64 {
            let chunk = core::cmp::min(INLINE_PTY_WRITE_CHUNK, count as u64 - sent);
            let mut req = TronaMsg::zeroed();
            let mut resp = TronaMsg::zeroed();
            req.label = label;
            req.length = 2 + ((chunk + 7) / 8);
            req.regs[0] = pty_id as u64;
            req.regs[1] = chunk;
            let dst = &raw mut req.regs[2] as *mut u8;
            core::ptr::copy_nonoverlapping(src.add(sent as usize), dst, chunk as usize);
            let err = ipc::call_ctx(
                crate::ipc_ctx(),
                crate::posix_ttysrv_ep(),
                &raw const req,
                &raw mut resp,
            );
            if err != 0 || resp.label != TRONA_OK {
                break;
            }
            sent += chunk;
        }
        (*reply).label = if sent > 0 || count == 0 {
            TRONA_OK
        } else {
            TRONA_INVALID_OPERATION
        };
        (*reply).length = 1;
        (*reply).regs[0] = sent;
    }
}

pub(crate) unsafe fn open_char_device_as_slot(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    vnode: crate::vfs_core::vnode::VnodeHandle,
    flags: u32,
    reply: *mut TronaMsg,
) {
    unsafe {
        let (node_kind, sub_id, generation) = match state.vnodes.get(vnode) {
            Some(vn) => match decode_device_inode(vn.id) {
                Some((kind, sub_id)) => (kind, sub_id, vn.backend_seq),
                None => {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    (*reply).length = 0;
                    return;
                }
            },
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return;
            }
        };

        let accmode = flags & O_ACCMODE;
        if accmode > O_RDWR {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let (dev_type, pty_id, open_generation) = match node_kind {
            DN_CONSOLE => (DEV_CONSOLE, 0, 0),
            DN_NULL => (DEV_NULL, 0, 0),
            DN_ZERO => (DEV_ZERO, 0, 0),
            DN_FB0 => (DEV_FB0, 0, 0),
            DN_URANDOM => (DEV_URANDOM, 0, 0),
            DN_PTMX => match alloc_ptmx() {
                Ok(pty_id) => (DEV_PTMX, pty_id, 0),
                Err(err) => {
                    (*reply).label = err;
                    (*reply).length = 0;
                    return;
                }
            },
            DN_TTY_ALIAS => match resolve_controlling_tty(state, cli_handle) {
                Some(runtime) => runtime,
                None => {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    (*reply).length = 0;
                    return;
                }
            },
            DN_PTY_SLAVE => (DEV_PTY_SLAVE, sub_id, generation),
            _ => {
                (*reply).label = TRONA_INVALID_OPERATION;
                (*reply).length = 0;
                return;
            }
        };

        if dev_type == DEV_PTY_SLAVE {
            let status = open_pty_slave(pty_id, open_generation);
            if status != TRONA_OK {
                (*reply).label = status;
                (*reply).length = 0;
                return;
            }
        }

        let Some(fd) = state.alloc_device_client_slot(
            cli_handle,
            vnode,
            dev_type,
            pty_id,
            open_generation,
            flags,
        ) else {
            if dev_type == DEV_PTMX || dev_type == DEV_PTY_SLAVE {
                close_pty_side(pty_id, dev_type);
            }
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return;
        };
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = fd as u64;
    }
}

pub(crate) unsafe fn handle_device_read_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        if fd < 0 {
            return false;
        }
        let Some((dev_type, pty_id, _generation, flags, _vnode)) =
            device_fd_view(state, cli_handle, fd as usize)
        else {
            return false;
        };
        if (flags & O_ACCMODE) == O_WRONLY {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return true;
        }

        let count = core::cmp::min((*msg).regs[1] as usize, INLINE_DEVICE_READ_MAX);
        if count == 0 {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return true;
        }
        match dev_type {
            DEV_NULL => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
            }
            DEV_ZERO => fill_zero_read_reply(count, reply),
            DEV_URANDOM => fill_urandom_read_reply(count, reply),
            DEV_CONSOLE | DEV_PTMX | DEV_PTY_SLAVE => {
                let Some(tty_id) = crate::fileops::tty_wait::tty_id_for_device(dev_type, pty_id)
                else {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    (*reply).length = 0;
                    return true;
                };
                let Some(side) = crate::fileops::tty_wait::tty_side_for_device(dev_type) else {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    (*reply).length = 0;
                    return true;
                };
                match crate::fileops::tty_wait::try_tty_read_to_reply(tty_id, side, count, reply) {
                    Ok(true) => {}
                    Ok(false) if (flags & O_NONBLOCK) != 0 => {
                        (*reply).label = TRONA_WOULD_BLOCK;
                        (*reply).length = 0;
                    }
                    Ok(false) => {
                        crate::fileops::tty_wait::defer_tty_read(
                            state, cli_handle, tty_id, side, count, reply,
                        );
                    }
                    Err(err) => {
                        (*reply).label = err;
                        (*reply).length = 0;
                    }
                }
            }
            _ => {
                (*reply).label = TRONA_INVALID_OPERATION;
                (*reply).length = 0;
            }
        }
        true
    }
}

pub(crate) unsafe fn handle_device_write_owned(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        if fd < 0 {
            return false;
        }
        let Some((dev_type, pty_id, _generation, flags, _vnode)) =
            device_fd_view(state, cli_handle, fd as usize)
        else {
            return false;
        };
        if (flags & O_ACCMODE) == O_RDONLY {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return true;
        }

        let count = core::cmp::min((*msg).regs[1] as usize, INLINE_DEVICE_WRITE_MAX);
        match dev_type {
            DEV_CONSOLE => console_write(msg, count, reply),
            DEV_NULL | DEV_ZERO | DEV_URANDOM => {
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = count as u64;
            }
            DEV_PTMX | DEV_PTY_SLAVE => pty_write(msg, pty_id, dev_type, count, reply),
            _ => {
                (*reply).label = TRONA_INVALID_OPERATION;
                (*reply).length = 0;
            }
        }
        true
    }
}

pub(crate) fn poll_bits_for_device(dev_type: u8, pty_id: u32, events: i16) -> i16 {
    match dev_type {
        DEV_CONSOLE => pty_poll(
            crate::fileops::tty_wait::CONSOLE_TTY_ID,
            DEV_PTY_SLAVE,
            events,
        ),
        DEV_PTMX | DEV_PTY_SLAVE => pty_poll(pty_id, dev_type, events),
        DEV_NULL | DEV_ZERO | DEV_URANDOM => events & (POLLIN | POLLOUT),
        DEV_FB0 => events & POLLOUT,
        _ => POLLNVAL,
    }
}

pub(crate) fn is_tty_fd(state: &VfsState, cli_handle: ClientHandle, fd: usize) -> bool {
    matches!(
        device_fd_view(state, cli_handle, fd),
        Some((DEV_CONSOLE, _, _, _, _))
            | Some((DEV_PTMX, _, _, _, _))
            | Some((DEV_PTY_SLAVE, _, _, _, _))
    )
}

pub(crate) unsafe fn handle_device_ioctl_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        if fd < 0 {
            return false;
        }
        let Some((dev_type, pty_id, _generation, _flags, _vnode)) =
            device_fd_view(state, cli_handle, fd as usize)
        else {
            return false;
        };
        let request = (*msg).regs[1];
        let arg = (*msg).regs[2];
        let badge = match state.clients.get(cli_handle) {
            Some(client) => client.badge,
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
                return true;
            }
        };

        match request {
            TIOCGPTN => {
                if dev_type != DEV_PTMX && dev_type != DEV_PTY_SLAVE {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    (*reply).length = 0;
                    return true;
                }
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = pty_id as u64;
                return true;
            }
            TIOCSWINSZ => {
                (*reply).label = TRONA_OK;
                (*reply).length = 0;
                return true;
            }
            _ => {}
        }

        if dev_type != DEV_CONSOLE && dev_type != DEV_PTMX && dev_type != DEV_PTY_SLAVE {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return true;
        }

        let tty_pty_id =
            crate::fileops::tty_wait::tty_id_for_device(dev_type, pty_id).unwrap_or(pty_id);
        match request {
            TIOCGPGRP => {
                ttysrv_ioctl(tty_pty_id, request, 0, 0, 0, reply);
            }
            TIOCSPGRP => {
                let mut caller_sid = 0u64;
                if !init_call1(INIT_GETSID_BADGE, badge, &raw mut caller_sid) {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    (*reply).length = 0;
                    return true;
                }
                ttysrv_ioctl(tty_pty_id, request, arg, caller_sid, 0, reply);
                if (*reply).label == TRONA_OK {
                    let _ = init_call3(INIT_SET_SESSION_TTY_PGRP, badge, arg, 0);
                }
            }
            TIOCGSID => {
                ttysrv_ioctl(tty_pty_id, request, 0, 0, 0, reply);
            }
            TIOCSCTTY => {
                let mut caller_sid = 0u64;
                let mut caller_pgid = 0u64;
                if !init_call1(INIT_GETSID_BADGE, badge, &raw mut caller_sid)
                    || !init_call1(INIT_GETPGID_BADGE, badge, &raw mut caller_pgid)
                {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    (*reply).length = 0;
                    return true;
                }
                ttysrv_ioctl(tty_pty_id, request, 0, caller_sid, caller_pgid, reply);
                if (*reply).label == TRONA_OK {
                    let _ = init_call3(
                        INIT_SET_SESSION_TTY,
                        badge,
                        tty_dev_id_for_runtime(dev_type, tty_pty_id),
                        caller_pgid,
                    );
                }
            }
            TIOCNOTTY => {
                let mut caller_sid = 0u64;
                if !init_call1(INIT_GETSID_BADGE, badge, &raw mut caller_sid) {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    (*reply).length = 0;
                    return true;
                }
                ttysrv_ioctl(tty_pty_id, request, 0, caller_sid, 0, reply);
                if (*reply).label == TRONA_OK {
                    let _ = init_call3(INIT_CLEAR_SESSION_TTY, badge, 0, 0);
                }
            }
            TIOCGWINSZ => {
                ttysrv_ioctl(tty_pty_id, request, 0, 0, 0, reply);
                if (*reply).label == TRONA_INVALID_OPERATION {
                    (*reply).label = TRONA_OK;
                    (*reply).length = 2;
                    (*reply).regs[0] = 24;
                    (*reply).regs[1] = 80;
                }
            }
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                (*reply).length = 0;
            }
        }
        true
    }
}

pub(crate) unsafe fn handle_device_tcgetattr_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        if fd < 0 {
            return false;
        }
        let Some((dev_type, pty_id, _generation, _flags, _vnode)) =
            device_fd_view(state, cli_handle, fd as usize)
        else {
            return false;
        };

        if dev_type == DEV_CONSOLE || dev_type == DEV_PTY_SLAVE || dev_type == DEV_PTMX {
            let Some(tty_id) = crate::fileops::tty_wait::tty_id_for_device(dev_type, pty_id) else {
                (*reply).label = TRONA_INVALID_OPERATION;
                (*reply).length = 0;
                return true;
            };
            let mut req = TronaMsg::zeroed();
            let mut resp = TronaMsg::zeroed();
            req.label = POSIX_TTYSRV_PTY_TCGETATTR;
            req.length = 1;
            req.regs[0] = tty_id as u64;
            let err = ipc::call_ctx(
                crate::ipc_ctx(),
                crate::posix_ttysrv_ep(),
                &raw const req,
                &raw mut resp,
            );
            if err != 0 || resp.label != TRONA_OK {
                (*reply).label = TRONA_INVALID_OPERATION;
                (*reply).length = 0;
            } else {
                (*reply).label = TRONA_OK;
                (*reply).length = resp.length;
                for idx in 0..resp.length as usize {
                    (*reply).regs[idx] = resp.regs[idx];
                }
            }
            return true;
        }

        (*reply).label = TRONA_INVALID_OPERATION;
        (*reply).length = 0;
        true
    }
}

pub(crate) unsafe fn handle_device_tcsetattr_owned(
    state: &VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        if fd < 0 {
            return false;
        }
        let Some((dev_type, pty_id, _generation, _flags, _vnode)) =
            device_fd_view(state, cli_handle, fd as usize)
        else {
            return false;
        };

        if dev_type == DEV_CONSOLE || dev_type == DEV_PTY_SLAVE || dev_type == DEV_PTMX {
            let Some(tty_id) = crate::fileops::tty_wait::tty_id_for_device(dev_type, pty_id) else {
                (*reply).label = TRONA_INVALID_OPERATION;
                (*reply).length = 0;
                return true;
            };
            let mut req = TronaMsg::zeroed();
            let mut resp = TronaMsg::zeroed();
            req.label = POSIX_TTYSRV_PTY_TCSETATTR;
            req.length = (*msg).length;
            req.regs[0] = tty_id as u64;
            for idx in 1..(*msg).length as usize {
                req.regs[idx] = (*msg).regs[idx];
            }
            let err = ipc::call_ctx(
                crate::ipc_ctx(),
                crate::posix_ttysrv_ep(),
                &raw const req,
                &raw mut resp,
            );
            (*reply).label = if err == 0 {
                resp.label
            } else {
                TRONA_INVALID_OPERATION
            };
            (*reply).length = 0;
            return true;
        }

        (*reply).label = TRONA_INVALID_OPERATION;
        (*reply).length = 0;
        true
    }
}

/// Backend RPC completion routing for device-side ttysrv ops.
///
/// Returns `true` only when this dispatcher has shipped the saved
/// reply. Returns `false` so the cascade falls through to the default
/// arm; per-op routing for `BACKEND_OP_TTYSRV_*` (provision-stdio /
/// pty-lookup / pty-read) lands here.
pub(crate) unsafe fn complete_device_op(
    _state: &mut VfsState,
    _completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    false
}
