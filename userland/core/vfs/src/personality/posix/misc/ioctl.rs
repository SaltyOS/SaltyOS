// SPDX-License-Identifier: GPL-2.0-only
//! ioctl dispatch for terminal, network, and framebuffer devices.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;
use trona::types::posix::*;

use crate::owner::VfsState;
use crate::server::consts::*;
use crate::server::types::*;
use crate::personality::posix::consts::*;
use crate::ipc_ctx;

const fn tty_dev_for_vfs_device(dev_type: u8, pty_id: u64) -> u64 {
    if dev_type == DEV_CONSOLE {
        tty_dev_for_console()
    } else {
        tty_dev_for_pts(pty_id)
    }
}

unsafe fn procmgr_call1(label: u64, arg0: u64, out0: *mut u64) -> bool {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = label;
        msg.length = 1;
        msg.regs[0] = arg0;
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona::caps::procmgr_ep(),
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            return false;
        }
        if !out0.is_null() {
            *out0 = reply.regs[0];
        }
        true
    }
}

unsafe fn procmgr_call3(label: u64, arg0: u64, arg1: u64, arg2: u64) -> bool {
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = label;
        msg.length = 3;
        msg.regs[0] = arg0;
        msg.regs[1] = arg1;
        msg.regs[2] = arg2;
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona::caps::procmgr_ep(),
            &raw const msg,
            &raw mut reply,
        );
        err == 0 && reply.label == TRONA_OK
    }
}

pub(crate) unsafe fn handle_ioctl(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let request = (*msg).regs[1];
        let arg = (*msg).regs[2];

        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let cli = match state.clients.get(cli_handle) {
            Some(c) => c,
            None => { (*reply).label = TRONA_INVALID_ARGUMENT; return; }
        };
        let slot = &cli.objects[fd as usize];
        if !slot.is_live() {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let kind = slot.kind();
        let device = slot.device_info();
        let badge = cli.badge;

        fn is_net_ioctl(request: u64) -> bool {
            matches!(
                request,
                0x8910 | 0x8912 | 0x8913 | 0x8915 | 0x8919 | 0x891B | 0x8933
            )
        }

        if kind == ObjectKind::Device && device.map(|d| d.dev_type) == Some(DEV_FB0) {
            handle_ioctl_fb0(request, reply);
            return;
        }

        if kind == ObjectKind::InetSocket && is_net_ioctl(request) {
            let mut nreq = TronaMsg::zeroed();
            let mut nreply = TronaMsg::zeroed();
            nreq.label = NET_GET_CONFIG;
            let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NETSRV_EP, &raw const nreq, &raw mut nreply);
            if err != 0 || nreply.label != TRONA_OK {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }

            let our_ip = nreply.regs[1] as u32;
            let subnet_mask = nreply.regs[2] as u32;
            let flags = if our_ip != 0 {
                0x1u64 | 0x2u64 | 0x40u64 | 0x1000u64
            } else {
                0
            };

            (*reply).label = TRONA_OK;
            match request {
                0x8910 => {
                    (*reply).length = 1;
                    (*reply).regs[0] = 1;
                }
                0x8912 => {
                    (*reply).length = 1;
                    (*reply).regs[0] = our_ip as u64;
                }
                0x8913 => {
                    (*reply).length = 1;
                    (*reply).regs[0] = flags;
                }
                0x8915 => {
                    (*reply).length = 1;
                    (*reply).regs[0] = our_ip as u64;
                }
                0x8919 => {
                    let broadcast = if our_ip != 0 && subnet_mask != 0 {
                        ((our_ip & subnet_mask) | !subnet_mask) as u64
                    } else {
                        0
                    };
                    (*reply).length = 1;
                    (*reply).regs[0] = broadcast;
                }
                0x891B => {
                    (*reply).length = 1;
                    (*reply).regs[0] = subnet_mask as u64;
                }
                0x8933 => {
                    (*reply).length = 1;
                    (*reply).regs[0] = 1;
                }
                _ => {
                    (*reply).label = TRONA_INVALID_OPERATION;
                }
            }
            let _ = arg;
            return;
        }

        // Terminal ioctls — supported by both console and PTY devices
        let Some(device) = device else {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        };
        if kind != ObjectKind::Device
            || (device.dev_type != DEV_CONSOLE && device.dev_type != DEV_PTY_SLAVE && device.dev_type != DEV_PTMX)
        {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let pty_id_u64 = if device.dev_type == DEV_PTY_SLAVE || device.dev_type == DEV_PTMX {
            device.pty_id as u64
        } else {
            0u64
        };
        let tty_dev = tty_dev_for_vfs_device(device.dev_type, pty_id_u64);

        match request {
            // TIOCGPGRP: get foreground process group
            0x540F => {
                let mut treq = TronaMsg::zeroed();
                let mut treply = TronaMsg::zeroed();
                treq.label = POSIX_TTYSRV_PTY_IOCTL;
                treq.regs[0] = pty_id_u64;
                treq.regs[1] = 0x540F; // TIOCGPGRP
                treq.regs[2] = 0;
                treq.regs[3] = 0;
                treq.regs[4] = 0;
                treq.length = 5;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const treq, &raw mut treply);
                if err != 0 || treply.label != TRONA_OK {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    return;
                }
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = treply.regs[0];
            }
            // TIOCSPGRP: set foreground process group
            0x5410 => {
                let mut caller_sid = 0u64;
                if !procmgr_call1(PM_GETSID_BADGE, badge, &raw mut caller_sid) {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    return;
                }
                let mut treq = TronaMsg::zeroed();
                let mut treply = TronaMsg::zeroed();
                treq.label = POSIX_TTYSRV_PTY_IOCTL;
                treq.regs[0] = pty_id_u64;
                treq.regs[1] = 0x5410; // TIOCSPGRP
                treq.regs[2] = (*msg).regs[2]; // pgid
                treq.regs[3] = caller_sid;
                treq.regs[4] = 0;
                treq.length = 5;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const treq, &raw mut treply);
                (*reply).label = if err == 0 {
                    treply.label
                } else {
                    TRONA_INVALID_OPERATION
                };
                (*reply).length = 0;
                if (*reply).label == TRONA_OK {
                    let _ = procmgr_call3(
                        PM_SET_SESSION_TTY_PGRP,
                        badge,
                        (*msg).regs[2],
                        0,
                    );
                }
            }
            // TIOCSCTTY: acquire controlling tty
            0x540E => {
                let mut caller_sid = 0u64;
                let mut caller_pgid = 0u64;
                if !procmgr_call1(PM_GETSID_BADGE, badge, &raw mut caller_sid)
                    || !procmgr_call1(PM_GETPGID_BADGE, badge, &raw mut caller_pgid)
                {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    return;
                }
                let mut treq = TronaMsg::zeroed();
                let mut treply = TronaMsg::zeroed();
                treq.label = POSIX_TTYSRV_PTY_IOCTL;
                treq.regs[0] = pty_id_u64;
                treq.regs[1] = 0x540E; // TIOCSCTTY
                treq.regs[2] = 0;
                treq.regs[3] = caller_sid;
                treq.regs[4] = caller_pgid;
                treq.length = 5;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const treq, &raw mut treply);
                (*reply).label = if err == 0 {
                    treply.label
                } else {
                    TRONA_INVALID_OPERATION
                };
                (*reply).length = 0;
                if (*reply).label == TRONA_OK {
                    let _ = procmgr_call3(PM_SET_SESSION_TTY, badge, tty_dev, caller_pgid);
                }
            }
            // TIOCNOTTY: release controlling tty
            0x5422 => {
                let mut caller_sid = 0u64;
                if !procmgr_call1(PM_GETSID_BADGE, badge, &raw mut caller_sid) {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    return;
                }
                let mut treq = TronaMsg::zeroed();
                let mut treply = TronaMsg::zeroed();
                treq.label = POSIX_TTYSRV_PTY_IOCTL;
                treq.regs[0] = pty_id_u64;
                treq.regs[1] = 0x5422; // TIOCNOTTY
                treq.regs[2] = 0;
                treq.regs[3] = caller_sid;
                treq.regs[4] = 0;
                treq.length = 5;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const treq, &raw mut treply);
                (*reply).label = if err == 0 {
                    treply.label
                } else {
                    TRONA_INVALID_OPERATION
                };
                (*reply).length = 0;
                if (*reply).label == TRONA_OK {
                    let _ = procmgr_call3(PM_CLEAR_SESSION_TTY, badge, 0, 0);
                }
            }
            // TIOCGPTN: get pty number for a ptmx fd
            0x80045430 => {
                if device.dev_type != DEV_PTMX && device.dev_type != DEV_PTY_SLAVE {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    return;
                }
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = pty_id_u64;
            }
            // TIOCGSID: get controlling session id
            0x5429 => {
                let mut treq = TronaMsg::zeroed();
                let mut treply = TronaMsg::zeroed();
                treq.label = POSIX_TTYSRV_PTY_IOCTL;
                treq.regs[0] = pty_id_u64;
                treq.regs[1] = 0x5429;
                treq.regs[2] = 0;
                treq.regs[3] = 0;
                treq.regs[4] = 0;
                treq.length = 5;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const treq, &raw mut treply);
                if err != 0 || treply.label != TRONA_OK {
                    (*reply).label = TRONA_INVALID_OPERATION;
                    return;
                }
                (*reply).label = TRONA_OK;
                (*reply).length = 1;
                (*reply).regs[0] = treply.regs[0];
            }
            // TIOCGWINSZ: get terminal window size
            0x5413 => {
                let mut treq = TronaMsg::zeroed();
                let mut treply = TronaMsg::zeroed();
                treq.label = POSIX_TTYSRV_PTY_IOCTL;
                treq.regs[0] = pty_id_u64;
                treq.regs[1] = 0x5413; // TIOCGWINSZ
                treq.regs[2] = 0;
                treq.regs[3] = badge;
                treq.length = 4;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const treq, &raw mut treply);
                if err != 0 || treply.label != TRONA_OK {
                    // Fallback to default 80x24
                    (*reply).label = TRONA_OK;
                    (*reply).length = 2;
                    (*reply).regs[0] = 24;
                    (*reply).regs[1] = 80;
                    return;
                }
                (*reply).label = TRONA_OK;
                (*reply).length = 2;
                (*reply).regs[0] = treply.regs[0];
                (*reply).regs[1] = treply.regs[1];
            }
            // TIOCSWINSZ: set terminal window size
            0x5414 => {
                let mut treq = TronaMsg::zeroed();
                let mut treply = TronaMsg::zeroed();
                let ws = arg as *const u16;
                if ws.is_null() {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
                let rows = *ws as u64;
                let cols = *ws.add(1) as u64;
                treq.label = POSIX_TTYSRV_PTY_IOCTL;
                treq.regs[0] = pty_id_u64;
                treq.regs[1] = 0x5414; // TIOCSWINSZ
                treq.regs[2] = rows;
                treq.regs[3] = cols;
                treq.regs[4] = 0;
                treq.length = 5;
                let err =
                    ipc::call_ctx(ipc_ctx(), VFS_CAP_POSIX_TTYSRV_EP, &raw const treq, &raw mut treply);
                (*reply).label = if err == 0 {
                    treply.label
                } else {
                    TRONA_INVALID_OPERATION
                };
                (*reply).length = 0;
            }
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
            }
        }
    }
}

pub(crate) unsafe fn handle_ioctl_fb0(request: u64, reply: *mut TronaMsg) {
    unsafe {
        match request {
            // FBIOGET_VSCREENINFO
            0x4600 => {
                (*reply).label = TRONA_OK;
                (*reply).length = 5;
                (*reply).regs[0] = crate::FB_WIDTH as u64;
                (*reply).regs[1] = crate::FB_HEIGHT as u64;
                (*reply).regs[2] = crate::FB_BPP as u64;
                (*reply).regs[3] = ((crate::FB_RED_POS as u64) << 24)
                    | ((crate::FB_RED_SIZE as u64) << 16)
                    | ((crate::FB_GREEN_POS as u64) << 8)
                    | (crate::FB_GREEN_SIZE as u64);
                (*reply).regs[4] =
                    ((crate::FB_BLUE_POS as u64) << 24) | ((crate::FB_BLUE_SIZE as u64) << 16);
            }
            // FBIOGET_FSCREENINFO
            0x4602 => {
                (*reply).label = TRONA_OK;
                (*reply).length = 3;
                (*reply).regs[0] = crate::FB_PITCH as u64;
                (*reply).regs[1] = crate::FB_HEIGHT as u64 * crate::FB_PITCH as u64;
                (*reply).regs[2] = 0; // type = packed pixels
            }
            _ => {
                (*reply).label = TRONA_INVALID_ARGUMENT;
            }
        }
    }
}
