// SPDX-License-Identifier: GPL-2.0-only
//! POSIX personality modules for VFS.

pub(crate) mod at_ops;
pub(crate) mod inet;
pub(crate) mod misc;
pub(crate) mod poll;
pub(crate) mod procfs;
pub(crate) mod socket;

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
use trona::protocol::posix::*;
use trona::protocol::vfs::*;
use trona::types::core::*;
use trona::types::posix::*;

use crate::client;
use crate::consts::*;

/// Dispatch a POSIX-specific VFS label.
///
/// Returns `Some(skip_reply)` if the label was handled, `None` if unrecognised
/// (caller should fall through to its own default arm).
pub(crate) unsafe fn dispatch(
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    badge: u64,
) -> Option<bool> {
    unsafe {
        let mut skip_reply = false;
        match (*msg).label {
            VFS_LSTAT => {
                at_ops::handle_lstat(msg, reply, badge);
            }
            VFS_ACCESS => {
                crate::fileops::handle_access(msg, reply, badge);
            }
            VFS_POLL => {
                skip_reply = poll::handle_poll(msg, reply, badge);
            }
            VFS_SHM_OPEN => {
                skip_reply = misc::handle_shm_open(msg, reply, badge);
            }
            VFS_SHM_UNLINK => {
                skip_reply = misc::handle_shm_unlink(msg, reply);
            }
            VFS_FTRUNCATE => {
                skip_reply = misc::handle_ftruncate(msg, reply, badge);
            }
            VFS_SOCKET => {
                skip_reply = socket::handle_socket(msg, reply, badge);
            }
            VFS_BIND => {
                if (*msg).regs[1] == AF_INET as u64 {
                    skip_reply = inet::handle_inet_bind(msg, reply, badge);
                } else {
                    skip_reply = socket::handle_bind(msg, reply, badge);
                }
            }
            VFS_LISTEN => {
                let fd = (*msg).regs[0] as i32;
                let cli = client::get_client(badge);
                if !cli.is_null()
                    && fd >= 0
                    && fd < (*cli).objects_cap as i32
                    && (*(*cli).objects.add(fd as usize)).active != 0
                    && (*(*cli).objects.add(fd as usize)).obj_type == OBJ_TYPE_INET_SOCKET
                {
                    skip_reply = inet::handle_inet_listen(msg, reply, badge);
                } else {
                    skip_reply = socket::handle_listen(msg, reply, badge);
                }
            }
            VFS_ACCEPT => {
                let fd = (*msg).regs[0] as i32;
                let cli = client::get_client(badge);
                if !cli.is_null()
                    && fd >= 0
                    && fd < (*cli).objects_cap as i32
                    && (*(*cli).objects.add(fd as usize)).active != 0
                    && (*(*cli).objects.add(fd as usize)).obj_type == OBJ_TYPE_INET_SOCKET
                {
                    skip_reply = inet::handle_inet_accept(msg, reply, badge);
                } else {
                    skip_reply = socket::handle_accept(msg, reply, badge);
                }
            }
            VFS_CONNECT => {
                let fd = (*msg).regs[0] as i32;
                let cli = client::get_client(badge);
                if !cli.is_null()
                    && fd >= 0
                    && fd < (*cli).objects_cap as i32
                    && (*(*cli).objects.add(fd as usize)).active != 0
                    && (*(*cli).objects.add(fd as usize)).obj_type == OBJ_TYPE_INET_SOCKET
                {
                    skip_reply = inet::handle_inet_connect(msg, reply, badge);
                } else {
                    skip_reply = socket::handle_connect(msg, reply, badge);
                }
            }
            VFS_SENDMSG => {
                let fd = (*msg).regs[0] as i32;
                let cli = client::get_client(badge);
                if !cli.is_null()
                    && fd >= 0
                    && fd < (*cli).objects_cap as i32
                    && (*(*cli).objects.add(fd as usize)).active != 0
                    && (*(*cli).objects.add(fd as usize)).obj_type == OBJ_TYPE_INET_SOCKET
                {
                    if (*msg).regs[3] != 0 || (*msg).regs[4] != 0 {
                        skip_reply = inet::handle_inet_sendto(msg, reply, badge);
                    } else {
                        skip_reply = inet::handle_inet_write(
                            msg,
                            (*cli).objects.add(fd as usize),
                            (*cli).posix_ext.add(fd as usize),
                            reply,
                        );
                    }
                } else {
                    skip_reply = socket::handle_sendmsg(msg, reply, badge);
                }
            }
            VFS_RECVMSG => {
                let fd = (*msg).regs[0] as i32;
                let cli = client::get_client(badge);
                if !cli.is_null()
                    && fd >= 0
                    && fd < (*cli).objects_cap as i32
                    && (*(*cli).objects.add(fd as usize)).active != 0
                    && (*(*cli).objects.add(fd as usize)).obj_type == OBJ_TYPE_INET_SOCKET
                {
                    let inet_flags = (*msg).regs[2] as u32;
                    if (inet_flags & INET_RECV_FLAG_WANT_ADDR) != 0 {
                        skip_reply = inet::handle_inet_recvfrom(msg, reply, badge);
                    } else {
                        skip_reply = inet::handle_inet_read(
                            msg,
                            (*cli).objects.add(fd as usize),
                            (*cli).posix_ext.add(fd as usize),
                            reply,
                            badge,
                        );
                    }
                } else {
                    skip_reply = socket::handle_recvmsg(msg, reply, badge);
                }
            }
            VFS_SOCKPAIR => {
                skip_reply = socket::handle_sockpair(msg, reply, badge);
            }
            VFS_SHUTDOWN => {
                let fd = (*msg).regs[0] as i32;
                let cli = client::get_client(badge);
                if !cli.is_null()
                    && fd >= 0
                    && fd < (*cli).objects_cap as i32
                    && (*(*cli).objects.add(fd as usize)).active != 0
                    && (*(*cli).objects.add(fd as usize)).obj_type == OBJ_TYPE_INET_SOCKET
                {
                    skip_reply = inet::handle_inet_shutdown(msg, reply, badge);
                } else {
                    skip_reply = socket::handle_shutdown(msg, reply, badge);
                }
            }
            VFS_GETSOCKNAME => {
                skip_reply = inet::handle_inet_getsockname(msg, reply, badge);
            }
            VFS_GETPEERNAME => {
                skip_reply = inet::handle_inet_getpeername(msg, reply, badge);
            }
            VFS_SETSOCKOPT => {
                skip_reply = inet::handle_inet_setsockopt(msg, reply, badge);
            }
            VFS_GETSOCKOPT => {
                skip_reply = inet::handle_inet_getsockopt(msg, reply, badge);
            }
            VFS_ISATTY => {
                misc::handle_isatty(msg, reply, badge);
            }
            VFS_IOCTL => {
                misc::handle_ioctl(msg, reply, badge);
            }
            VFS_FCNTL => {
                misc::handle_fcntl(msg, reply, badge);
            }
            VFS_CHDIR => {
                misc::handle_chdir(msg, reply, badge);
            }
            VFS_GETCWD => {
                misc::handle_getcwd(msg, reply, badge);
            }
            VFS_TCGETATTR => {
                misc::handle_tcgetattr(msg, reply, badge);
            }
            VFS_TCSETATTR => {
                misc::handle_tcsetattr(msg, reply, badge);
            }
            VFS_EPOLL_CREATE => {
                poll::handle_epoll_create(reply, badge);
            }
            VFS_EPOLL_CTL => {
                poll::handle_epoll_ctl(msg, reply, badge);
            }
            VFS_EPOLL_WAIT => {
                skip_reply = poll::handle_epoll_wait(msg, reply, badge);
            }
            VFS_OPENAT => {
                at_ops::handle_openat(msg, reply, badge);
            }
            VFS_FSTATAT => {
                at_ops::handle_fstatat(msg, reply, badge);
            }
            VFS_UNLINKAT => {
                at_ops::handle_unlinkat(msg, reply, badge);
            }
            VFS_RENAMEAT => {
                at_ops::handle_renameat(msg, reply, badge);
            }
            VFS_MKDIRAT => {
                at_ops::handle_mkdirat(msg, reply, badge);
            }
            VFS_FACCESSAT => {
                at_ops::handle_faccessat(msg, reply, badge);
            }
            VFS_FCHMODAT => {
                at_ops::handle_fchmodat(msg, reply, badge);
            }
            VFS_FCHOWNAT => {
                at_ops::handle_fchownat(msg, reply, badge);
            }
            VFS_LINKAT => {
                at_ops::handle_linkat(msg, reply, badge);
            }
            VFS_SYMLINKAT => {
                at_ops::handle_symlinkat(msg, reply, badge);
            }
            VFS_READLINKAT => {
                at_ops::handle_readlinkat(msg, reply, badge);
            }
            VFS_UTIMENSAT => {
                at_ops::handle_utimensat(msg, reply, badge);
            }
            VFS_FCHMOD => {
                at_ops::handle_fchmod(msg, reply, badge);
            }
            VFS_FCHOWN => {
                at_ops::handle_fchown(msg, reply, badge);
            }
            _ => return None,
        }
        Some(skip_reply)
    }
}
