// SPDX-License-Identifier: GPL-2.0-only
//! Terminal attribute handlers: isatty, tcgetattr, tcsetattr.

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_posix::consts::*;
use trona_protocol::posix::*;
use trona_runtime::core::server_consts::*;
use uapi::*;

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

    let is_tty = match state.open_object_at(cli_handle, fd as usize) {
        Some(obj) if obj.kind() == ObjectKind::Device => {
            if let Some(device) = obj.device_info()
                && (device.dev_type == DEV_CONSOLE
                    || device.dev_type == DEV_PTY_SLAVE
                    || device.dev_type == DEV_PTMX)
            {
                1u64
            } else {
                0u64
            }
        }
        _ => 0u64,
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

        let (device, kind) = match state.open_object_at(cli_handle, fd as usize) {
            Some(obj) => match obj.device_info() {
                Some(d) => (d, obj.kind()),
                None => {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    return;
                }
            },
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        if kind != ObjectKind::Device {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        if device.dev_type == DEV_PTY_SLAVE {
            let mut treq = TronaMsg::zeroed();
            let mut treply = TronaMsg::zeroed();
            treq.label = POSIX_TTYSRV_PTY_TCGETATTR;
            treq.regs[0] = device.pty_id as u64;
            treq.length = 1;
            let err = ipc::call_ctx(
                ipc_ctx(),
                posix_ttysrv_ep(),
                &raw const treq,
                &raw mut treply,
            );
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
                trona_runtime::client::caps::console_ep(),
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

        let (device, kind) = match state.open_object_at(cli_handle, fd as usize) {
            Some(obj) => match obj.device_info() {
                Some(d) => (d, obj.kind()),
                None => {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    return;
                }
            },
            None => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
                return;
            }
        };
        if kind != ObjectKind::Device {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        if device.dev_type == DEV_PTY_SLAVE {
            let mut treq = TronaMsg::zeroed();
            let mut treply = TronaMsg::zeroed();
            treq.label = POSIX_TTYSRV_PTY_TCSETATTR;
            treq.regs[0] = device.pty_id as u64;
            let copy_len = if (*msg).length > 1 {
                (*msg).length - 1
            } else {
                0
            };
            for i in 0..copy_len as usize {
                treq.regs[i + 1] = (*msg).regs[i + 1];
            }
            treq.length = 1 + copy_len;
            let err = ipc::call_ctx(
                ipc_ctx(),
                posix_ttysrv_ep(),
                &raw const treq,
                &raw mut treply,
            );
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
                trona_runtime::client::caps::console_ep(),
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
