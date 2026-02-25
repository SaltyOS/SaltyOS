// SPDX-License-Identifier: GPL-2.0-only
//! POSIX fcntl, isatty, ioctl, chdir, getcwd, tcgetattr, shm operations.

use super::{pack_path, CAP_VFS_EP};
use crate::consts::*;
use crate::types::*;

#[repr(C)]
struct IoctlWinsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

/// File control operations (F_GETFL, F_SETFL, F_DUPFD, etc.).
/// Returns the result value on success, -1 on error.
pub unsafe fn posix_fcntl(fd: i32, cmd: i32, arg: i64) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_FCNTL;
        msg.length = 3;
        msg.regs[0] = fd as u64;
        msg.regs[1] = cmd as u64;
        msg.regs[2] = arg as u64;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Test whether `fd` refers to a terminal. Returns 1 if yes, 0 if not.
pub unsafe fn posix_isatty(fd: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_ISATTY;
        msg.length = 1;
        msg.regs[0] = fd as u64;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return 0;
        }
        reply.regs[0] as i32
    }
}

/// Generic device I/O control. Returns the result value, or -1 on error.
pub unsafe fn posix_ioctl(fd: i32, request: u64, arg: u64) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_IOCTL;
        msg.length = 3;
        msg.regs[0] = fd as u64;
        msg.regs[1] = request;
        msg.regs[2] = arg;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }

        match request {
            TIOCGPGRP => {
                if arg != 0 {
                    let pgrp_p = arg as *mut i32;
                    *pgrp_p = reply.regs[0] as i32;
                    return 0;
                }
            }
            TIOCGWINSZ => {
                if arg != 0 {
                    let rows = if reply.length >= 1 { reply.regs[0] } else { 0 };
                    let cols = if reply.length >= 2 { reply.regs[1] } else { 0 };

                    let ws = arg as *mut IoctlWinsize;
                    (*ws).ws_row = rows as u16;
                    (*ws).ws_col = cols as u16;
                    (*ws).ws_xpixel = 0;
                    (*ws).ws_ypixel = 0;
                    return 0;
                }
            }
            _ => {}
        }
        reply.regs[0] as i32
    }
}

/// Change the current working directory to `path`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_chdir(path: *const u8) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_CHDIR;
        let path_len = pack_path(&raw mut msg, 0, path, 128);
        msg.length = 1 + ((path_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        0
    }
}

/// Get the current working directory, writing the null-terminated path
/// into `buf` (up to `size` bytes). Returns 0 on success, -1 on error.
pub unsafe fn posix_getcwd(buf: *mut u8, size: u64) -> i32 {
    unsafe {
        if buf.is_null() || size == 0 {
            return -1;
        }

        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_GETCWD;
        msg.length = 1;
        msg.regs[0] = size;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }

        let path_len = reply.regs[0] as usize;
        let size_usize = size as usize;
        if path_len + 1 > size_usize {
            return -1;
        }
        let reply_data_bytes = (reply.length.saturating_sub(1) * 8) as usize;
        if path_len > reply_data_bytes {
            return -1;
        }

        let src = &reply.regs[1] as *const u64 as *const u8;
        for i in 0..path_len {
            *buf.add(i) = *src.add(i);
        }
        *buf.add(path_len) = 0;
        0
    }
}

/// Get terminal attributes for fd into `*termios_p`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_tcgetattr(fd: i32, termios_p: *mut crate::types::Termios) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_TCGETATTR;
        msg.length = 1;
        msg.regs[0] = fd as u64;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }

        // Unpack: regs[0]=c_iflag, regs[1]=c_oflag, regs[2]=c_cflag, regs[3]=c_lflag
        // regs[4]=c_ispeed, regs[5]=c_ospeed, regs[6..9]=c_cc[0..31] packed as 4 u64s
        (*termios_p).c_iflag = reply.regs[0] as u32;
        (*termios_p).c_oflag = reply.regs[1] as u32;
        (*termios_p).c_cflag = reply.regs[2] as u32;
        (*termios_p).c_lflag = reply.regs[3] as u32;
        (*termios_p).c_ispeed = reply.regs[4] as u32;
        (*termios_p).c_ospeed = reply.regs[5] as u32;
        (*termios_p).c_line = 0;
        // Unpack c_cc from regs[6..9] (4 u64s = 32 bytes)
        let src = &reply.regs[6] as *const u64 as *const u8;
        for i in 0..32 {
            (*termios_p).c_cc[i] = *src.add(i);
        }
        0
    }
}

/// Set terminal attributes for fd from `*termios_p`.
/// `action` controls when changes take effect (TCSANOW/TCSADRAIN/TCSAFLUSH).
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_tcsetattr(
    fd: i32,
    action: i32,
    termios_p: *const crate::types::Termios,
) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_TCSETATTR;
        msg.length = 11;
        msg.regs[0] = fd as u64;
        msg.regs[1] = action as u64;
        msg.regs[2] = (*termios_p).c_iflag as u64;
        msg.regs[3] = (*termios_p).c_oflag as u64;
        msg.regs[4] = (*termios_p).c_cflag as u64;
        msg.regs[5] = (*termios_p).c_lflag as u64;
        msg.regs[6] = (*termios_p).c_ispeed as u64;
        msg.regs[7] = (*termios_p).c_ospeed as u64;
        // Pack c_cc into regs[8..11] (4 u64s = 32 bytes)
        let dst = &mut msg.regs[8] as *mut u64 as *mut u8;
        for i in 0..32 {
            *dst.add(i) = (*termios_p).c_cc[i];
        }

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        0
    }
}

/// Open a POSIX shared memory object by `name` (e.g. "/myshm").
///
/// Strips the leading '/' per POSIX convention before sending to VFS.
/// Returns the shm fd on success, -1 on error.
pub unsafe fn posix_shm_open(name: *const u8, flags: i32) -> i32 {
    unsafe {
        // POSIX: shm names are "/name"; strip leading '/' before sending bare name to VFS
        let bare = if !name.is_null() && *name == b'/' {
            name.add(1)
        } else {
            name
        };
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_SHM_OPEN;
        msg.regs[0] = flags as u64;
        let name_len = pack_path(&raw mut msg, 1, bare, 128);
        msg.length = 2 + ((name_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Remove a POSIX shared memory object by name.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_shm_unlink(name: *const u8) -> i32 {
    unsafe {
        // POSIX: shm names are "/name"; strip leading '/' before sending bare name to VFS
        let bare = if !name.is_null() && *name == b'/' {
            name.add(1)
        } else {
            name
        };
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_SHM_UNLINK;
        let name_len = pack_path(&raw mut msg, 0, bare, 128);
        msg.length = 1 + ((name_len as u64 + 7) / 8);

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        0
    }
}

/// Framebuffer ioctl wrapper.
///
/// Sends POSIX_VFS_IOCTL with an fb-specific command and unpacks up to 5 result registers.
pub unsafe fn posix_fb_ioctl(fd: i32, cmd: u64, result: *mut [u64; 5]) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_IOCTL;
        msg.length = 3;
        msg.regs[0] = fd as u64;
        msg.regs[1] = cmd;
        msg.regs[2] = 0;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        if !result.is_null() {
            for i in 0..5 {
                (*result)[i] = reply.regs[i];
            }
        }
        0
    }
}

// Process-local umask cache. Fork copies the address space, so children
// inherit the value automatically. Single-threaded processes only.
static mut UMASK_CACHE: u32 = 0o022;

/// Return the current cached umask value.
pub(crate) unsafe fn get_umask() -> u32 {
    unsafe { core::ptr::read_volatile(&raw const UMASK_CACHE) }
}

/// Set the file creation mask. Returns the previous mask.
///
/// IPC to procmgr: regs[0] = new mask. Reply: regs[0] = old mask.
/// Also updates the local cache so file creation functions can apply it
/// without an extra IPC round-trip.
pub unsafe fn posix_umask(mask: u32) -> u32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_UMASK;
        msg.length = 1;
        msg.regs[0] = mask as u64;

        let cap_procmgr: u64 = 3; // CAP_PROCMGR_EP
        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            cap_procmgr,
            &raw const msg,
            &raw mut reply,
        );
        let old = if err != 0 || reply.label != SALTY_OK {
            let prev = core::ptr::read_volatile(&raw const UMASK_CACHE);
            core::ptr::write_volatile(&raw mut UMASK_CACHE, mask & 0o777);
            prev
        } else {
            core::ptr::write_volatile(&raw mut UMASK_CACHE, mask & 0o777);
            reply.regs[0] as u32
        };
        old
    }
}

/// fchmod(fd, mode) — change mode on open fd
/// IPC: reg[0]=fd, reg[1]=mode
pub unsafe fn posix_fchmod(fd: i32, mode: u32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_FCHMOD;
        msg.length = 2;
        msg.regs[0] = fd as u64;
        msg.regs[1] = mode as u64;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        0
    }
}

/// fchown(fd, uid, gid) — change owner on open fd
/// IPC: reg[0]=fd, reg[1]=uid, reg[2]=gid
pub unsafe fn posix_fchown(fd: i32, uid: u32, gid: u32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_VFS_FCHOWN;
        msg.length = 3;
        msg.regs[0] = fd as u64;
        msg.regs[1] = uid as u64;
        msg.regs[2] = gid as u64;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_VFS_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        0
    }
}
