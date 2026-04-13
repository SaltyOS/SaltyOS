// SPDX-License-Identifier: GPL-2.0-only
//! Terminal attribute handlers: isatty, tcgetattr, tcsetattr.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;

use crate::ipc_ctx;
use crate::owner::VfsState;
use crate::server::consts::*;
use crate::server::types::*;

pub(crate) unsafe fn handle_isatty(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    let fd = unsafe { (*msg).regs[0] } as i32;
    if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
        unsafe {
            (*reply).label = TRONA_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
        }
        return;
    }

    let is_tty = match state.clients.get(cli_handle) {
        Some(cli) => {
            let slot = &cli.objects[fd as usize];
            if let Some(device) = slot.device_info()
                && slot.is_live()
                && slot.kind() == ObjectKind::Device
                && (device.dev_type == DEV_CONSOLE
                    || device.dev_type == DEV_PTY_SLAVE
                    || device.dev_type == DEV_PTMX)
            {
                1u64
            } else {
                0u64
            }
        }
        None => 0u64,
    };

    unsafe {
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = is_tty;
    }
}

pub(crate) unsafe fn handle_tcgetattr(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let cli = match state.clients.get(cli_handle) {
            Some(c) => c,
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
        };
        let slot = &cli.objects[fd as usize];
        let Some(device) = slot.device_info() else {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        };
        if !slot.is_live() || slot.kind() != ObjectKind::Device {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        if device.dev_type == DEV_PTY_SLAVE {
            let mut treq = TronaMsg::zeroed();
            let mut treply = TronaMsg::zeroed();
            treq.label = POSIX_TTYSRV_PTY_TCGETATTR;
            treq.regs[0] = device.pty_id as u64;
            treq.length = 1;
            let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const treq, &raw mut treply);
            if err != 0 || treply.label != TRONA_OK {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
            (*reply).label = TRONA_OK;
            (*reply).length = treply.length;
            for i in 0..treply.length as usize {
                (*reply).regs[i] = treply.regs[i];
            }
        } else if device.dev_type == DEV_CONSOLE {
            let mut creq = TronaMsg::zeroed();
            let mut creply = TronaMsg::zeroed();
            creq.label = CONSOLE_TCGETATTR;
            creq.length = 0;
            let err = ipc::call_ctx(
                ipc_ctx(),
                trona::caps::console_ep(),
                &raw const creq,
                &raw mut creply,
            );
            if err != 0 || creply.label != TRONA_OK {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
            (*reply).label = TRONA_OK;
            (*reply).length = creply.length;
            for i in 0..creply.length as usize {
                (*reply).regs[i] = creply.regs[i];
            }
        } else {
            (*reply).label = TRONA_INVALID_OPERATION;
        }
    }
}

pub(crate) unsafe fn handle_tcsetattr(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let cli = match state.clients.get(cli_handle) {
            Some(c) => c,
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
        };
        let slot = &cli.objects[fd as usize];
        let Some(device) = slot.device_info() else {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        };
        if !slot.is_live() || slot.kind() != ObjectKind::Device {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        if device.dev_type == DEV_PTY_SLAVE {
            let mut treq = TronaMsg::zeroed();
            let mut treply = TronaMsg::zeroed();
            treq.label = POSIX_TTYSRV_PTY_TCSETATTR;
            treq.regs[0] = device.pty_id as u64;
            let copy_len = if (*msg).length > 1 { (*msg).length - 1 } else { 0 };
            for i in 0..copy_len as usize {
                treq.regs[i + 1] = (*msg).regs[i + 1];
            }
            treq.length = 1 + copy_len;
            let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const treq, &raw mut treply);
            if err != 0 || treply.label != TRONA_OK {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
            (*reply).label = TRONA_OK;
            (*reply).length = 0;
        } else if device.dev_type == DEV_CONSOLE {
            let mut creq = TronaMsg::zeroed();
            let mut creply = TronaMsg::zeroed();
            creq.label = CONSOLE_TCSETATTR;
            creq.length = (*msg).length;
            for i in 0..(*msg).length as usize {
                creq.regs[i] = (*msg).regs[i];
            }
            let err = ipc::call_ctx(
                ipc_ctx(),
                trona::caps::console_ep(),
                &raw const creq,
                &raw mut creply,
            );
            if err != 0 || creply.label != TRONA_OK {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
            (*reply).label = TRONA_OK;
            (*reply).length = 0;
        } else {
            (*reply).label = TRONA_INVALID_OPERATION;
        }
    }
}
