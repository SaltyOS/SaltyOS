// SPDX-License-Identifier: GPL-2.0-only
//! POSIX-owned device dispatch helpers.

use trona::consts::kernel::*;
use trona::ipc;
use trona::protocol::posix::*;
use trona::types::core::*;

use crate::owner::VfsState;
use crate::server::consts::*;
use crate::server::types::*;
use crate::ipc_ctx;

use crate::personality::posix::tty;
use crate::personality::posix::tty::pty;
use trona::consts::posix::{DEV_PTMX, DEV_PTY_SLAVE};

pub(crate) unsafe fn handle_device_read(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let device = match state.clients.get(cli_handle) {
            Some(cli) if fd >= 0 && (fd as usize) < MAX_CLIENT_OBJECTS => {
                cli.objects[fd as usize].device_info()
            }
            _ => None,
        };

        match device {
            Some(device) if device.dev_type == DEV_PTY_SLAVE => {
                pty::handle_pty_dev_read(state, cli_handle, fd, msg, reply)
            }
            Some(device) if device.dev_type == DEV_PTMX => {
                handle_ptmx_read(device.pty_id, msg, reply);
                false
            }
            Some(_) => {
                crate::fileops::rw::handle_read_owned(state, cli_handle, msg, reply);
                false
            }
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                false
            }
        }
    }
}

pub(crate) unsafe fn handle_device_write(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let device = match state.clients.get(cli_handle) {
            Some(cli) if fd >= 0 && (fd as usize) < MAX_CLIENT_OBJECTS => {
                cli.objects[fd as usize].device_info()
            }
            _ => None,
        };

        match device {
            Some(device) if device.dev_type == DEV_PTMX || device.dev_type == DEV_PTY_SLAVE => {
                handle_pty_write(device.dev_type, device.pty_id, msg, reply);
                false
            }
            Some(_) => {
                crate::fileops::rw::handle_write_owned(state, cli_handle, msg, reply);
                false
            }
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                false
            }
        }
    }
}

pub(crate) unsafe fn pre_close_device(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
) {
    unsafe {
        let device = match state.clients.get(cli_handle) {
            Some(cli) if fd >= 0 && (fd as usize) < MAX_CLIENT_OBJECTS => {
                cli.objects[fd as usize].device_info()
            }
            _ => None,
        };
        let Some(device) = device else {
            return;
        };
        if device.dev_type != DEV_PTY_SLAVE && device.dev_type != DEV_PTMX {
            return;
        }

        let mut treq = TronaMsg::zeroed();
        let mut treply = TronaMsg::zeroed();
        treq.label = POSIX_TTYSRV_PTY_CLOSE;
        treq.length = 2;
        treq.regs[0] = device.pty_id as u64;
        treq.regs[1] = if device.dev_type == DEV_PTMX { 1 } else { 0 };
        let _ = ipc::call_ctx(
            ipc_ctx(),
            VFS_CAP_POSIX_TTYSRV_EP,
            &raw const treq,
            &raw mut treply,
        );
    }
}

unsafe fn handle_ptmx_read(
    pty_id: u32,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let count = ((*msg).regs[1]).min(152);
        let mut treq = TronaMsg::zeroed();
        let mut treply = TronaMsg::zeroed();
        treq.label = POSIX_TTYSRV_PTY_READ;
        treq.regs[0] = pty_id as u64;
        treq.regs[1] = count;
        treq.regs[2] = 1;
        treq.length = 3;
        let err = ipc::call_ctx(
            ipc_ctx(),
            VFS_CAP_POSIX_TTYSRV_EP,
            &raw const treq,
            &raw mut treply,
        );
        if err != 0 || treply.label != TRONA_OK {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }
        let actual = treply.regs[0];
        (*reply).label = TRONA_OK;
        (*reply).length = 1 + (actual + 7) / 8;
        (*reply).regs[0] = actual;
        if actual > 0 {
            let src = &treply.regs[1] as *const u64 as *const u8;
            let dst = &raw mut (*reply).regs[1] as *mut u8;
            for index in 0..actual as usize {
                *dst.add(index) = *src.add(index);
            }
        }
    }
}

unsafe fn handle_pty_write(
    dev_type: u8,
    pty_id: u32,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let count = ((*msg).regs[1]).min(152);
        let label = if dev_type == DEV_PTMX {
            POSIX_TTYSRV_PTY_MASTER_WRITE
        } else {
            POSIX_TTYSRV_PTY_WRITE
        };
        let src = &(*msg).regs[2] as *const u64 as *const u8;
        let mut sent = 0u64;
        while sent < count {
            let mut treq = TronaMsg::zeroed();
            let mut treply = TronaMsg::zeroed();
            let chunk = (count - sent).min(136);
            treq.label = label;
            treq.regs[0] = pty_id as u64;
            treq.regs[1] = chunk;
            let dst = &raw mut treq.regs[2] as *mut u8;
            for index in 0..chunk as usize {
                *dst.add(index) = *src.add(sent as usize + index);
            }
            treq.length = 2 + (chunk + 7) / 8;
            let err = ipc::call_ctx(
                ipc_ctx(),
                VFS_CAP_POSIX_TTYSRV_EP,
                &raw const treq,
                &raw mut treply,
            );
            if err != 0 || treply.label != TRONA_OK {
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
