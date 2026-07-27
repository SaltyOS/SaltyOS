// SPDX-License-Identifier: GPL-2.0-only
//! POSIX personality dispatch — routes POSIX-specific VFS IPC labels.

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use trona_posix::types::*;
use trona_protocol::posix::posix::*;
use trona_protocol::posix::vfs::*;
use trona_runtime::core::server_consts::*;
use uapi::*;

use super::{at_ops, fd_ops, inet, misc, poll, socket, tty};
use crate::fileops::pipe;
use crate::owner::VfsState;
use crate::personality::posix::consts::*;
use crate::server::consts::*;
use crate::server::types::*;

/// Dispatch a POSIX-specific VFS label.
///
/// Returns `Some(skip_reply)` if the label was handled, `None` if unrecognised.
pub(crate) unsafe fn dispatch(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> Option<bool> {
    unsafe {
        let mut skip_reply = false;
        match (*msg).label {
            // File operations — redirect to _owned versions
            VFS_POSIX_OPEN => {
                skip_reply = crate::fileops::open::handle_open_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_STAT => {
                skip_reply = crate::fileops::stat::handle_stat_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_STAT_FOR_EXEC => {
                skip_reply =
                    crate::fileops::stat::handle_stat_for_exec_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_CANON_PATH => {
                crate::fileops::stat::handle_canon_path_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_FSTAT => {
                skip_reply =
                    crate::fileops::stat::handle_fstat_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_UNLINK => {
                crate::fileops::mutate::handle_unlink_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_RENAME => {
                crate::fileops::mutate::handle_rename_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_MKDIR => {
                crate::fileops::mutate::handle_mkdir_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_RMDIR => {
                crate::fileops::mutate::handle_rmdir_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_OPENDIR => {
                skip_reply =
                    crate::fileops::dir::handle_opendir_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_READDIR => {
                skip_reply =
                    crate::fileops::dir::handle_readdir_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_MKFIFO => {
                crate::fileops::mutate::handle_mkfifo_owned(state, cli_handle, msg, reply);
            }
            VFS_POSIX_ACCESS => {
                skip_reply =
                    crate::fileops::stat::handle_access_owned(state, cli_handle, msg, reply);
            }
            // POSIX pipe and fd duplication
            VFS_POSIX_PIPE => {
                pipe::handle_pipe(state, cli_handle, msg, reply);
            }
            VFS_POSIX_DUP => {
                fd_ops::handle_dup(state, cli_handle, msg, reply);
            }
            VFS_POSIX_DUP2 => {
                fd_ops::handle_dup2(state, cli_handle, msg, reply);
            }
            VFS_POSIX_DUP3 => {
                fd_ops::handle_dup3(state, cli_handle, msg, reply);
            }
            VFS_POSIX_CLONE_FDS => {
                fd_ops::handle_clone_fds(state, cli_handle, msg, reply);
            }
            // Stat variants
            VFS_POSIX_LSTAT => {
                skip_reply = at_ops::handle_lstat(state, cli_handle, msg, reply);
            }
            // Poll / epoll
            VFS_POSIX_POLL => {
                skip_reply = poll::handle_poll(state, cli_handle, msg, reply);
            }
            VFS_POSIX_EPOLL_CREATE => {
                poll::handle_epoll_create(state, cli_handle, reply);
            }
            VFS_POSIX_EPOLL_CTL => {
                poll::handle_epoll_ctl(state, cli_handle, msg, reply);
            }
            VFS_POSIX_EPOLL_WAIT => {
                skip_reply = poll::handle_epoll_wait(state, cli_handle, msg, reply);
            }
            // SHM
            VFS_POSIX_SHM_OPEN => {
                skip_reply = misc::handle_shm_open(state, cli_handle, msg, reply);
            }
            VFS_POSIX_SHM_UNLINK => {
                skip_reply = misc::handle_shm_unlink(state, cli_handle, msg, reply);
            }
            VFS_POSIX_FTRUNCATE => {
                skip_reply = misc::handle_ftruncate(state, cli_handle, msg, reply);
            }
            // Sockets
            VFS_POSIX_SOCKET => {
                skip_reply = socket::handle_socket(state, cli_handle, msg, reply);
            }
            VFS_POSIX_BIND => {
                if (*msg).regs[1] == AF_INET as u64 {
                    skip_reply = inet::handle_inet_bind(state, cli_handle, msg, reply);
                } else {
                    skip_reply = socket::handle_bind(state, cli_handle, msg, reply);
                }
            }
            VFS_POSIX_LISTEN => {
                let fd = (*msg).regs[0] as i32;
                let is_inet = is_fd_type(state, cli_handle, fd, ObjectKind::InetSocket);
                if is_inet {
                    skip_reply = inet::handle_inet_listen(state, cli_handle, msg, reply);
                } else {
                    skip_reply = socket::handle_listen(state, cli_handle, msg, reply);
                }
            }
            VFS_POSIX_ACCEPT => {
                let fd = (*msg).regs[0] as i32;
                let is_inet = is_fd_type(state, cli_handle, fd, ObjectKind::InetSocket);
                if is_inet {
                    skip_reply = inet::handle_inet_accept(state, cli_handle, msg, reply);
                } else {
                    skip_reply = socket::handle_accept(state, cli_handle, msg, reply);
                }
            }
            VFS_POSIX_CONNECT => {
                let fd = (*msg).regs[0] as i32;
                let is_inet = is_fd_type(state, cli_handle, fd, ObjectKind::InetSocket);
                if is_inet {
                    skip_reply = inet::handle_inet_connect(state, cli_handle, msg, reply);
                } else {
                    skip_reply = socket::handle_connect(state, cli_handle, msg, reply);
                }
            }
            VFS_POSIX_SENDMSG => {
                let fd = (*msg).regs[0] as i32;
                let is_inet = is_fd_type(state, cli_handle, fd, ObjectKind::InetSocket);
                if is_inet {
                    if (*msg).regs[3] != 0 || (*msg).regs[4] != 0 {
                        skip_reply = inet::handle_inet_sendto(state, cli_handle, msg, reply);
                    } else {
                        skip_reply = inet::handle_inet_write(state, cli_handle, fd, msg, reply);
                    }
                } else {
                    skip_reply = socket::handle_sendmsg(state, cli_handle, msg, reply);
                }
            }
            VFS_POSIX_RECVMSG => {
                let fd = (*msg).regs[0] as i32;
                let is_inet = is_fd_type(state, cli_handle, fd, ObjectKind::InetSocket);
                if is_inet {
                    let inet_flags = (*msg).regs[2] as u32;
                    if (inet_flags & INET_RECV_FLAG_WANT_ADDR) != 0 {
                        skip_reply = inet::handle_inet_recvfrom(state, cli_handle, msg, reply);
                    } else {
                        skip_reply = inet::handle_inet_read(state, cli_handle, fd, msg, reply);
                    }
                } else {
                    skip_reply = socket::handle_recvmsg(state, cli_handle, msg, reply);
                }
            }
            VFS_POSIX_SOCKPAIR => {
                skip_reply = socket::handle_sockpair(state, cli_handle, msg, reply);
            }
            VFS_POSIX_SHUTDOWN => {
                let fd = (*msg).regs[0] as i32;
                let is_inet = is_fd_type(state, cli_handle, fd, ObjectKind::InetSocket);
                if is_inet {
                    skip_reply = inet::handle_inet_shutdown(state, cli_handle, msg, reply);
                } else {
                    skip_reply = socket::handle_shutdown(state, cli_handle, msg, reply);
                }
            }
            VFS_POSIX_GETSOCKNAME => {
                skip_reply = inet::handle_inet_getsockname(state, cli_handle, msg, reply);
            }
            VFS_POSIX_GETPEERNAME => {
                skip_reply = inet::handle_inet_getpeername(state, cli_handle, msg, reply);
            }
            VFS_POSIX_SETSOCKOPT => {
                skip_reply = inet::handle_inet_setsockopt(state, cli_handle, msg, reply);
            }
            VFS_POSIX_GETSOCKOPT => {
                skip_reply = inet::handle_inet_getsockopt(state, cli_handle, msg, reply);
            }
            // Misc POSIX
            VFS_POSIX_ISATTY => {
                tty::handle_isatty(state, cli_handle, msg, reply);
            }
            VFS_POSIX_IOCTL => {
                misc::handle_ioctl(state, cli_handle, msg, reply);
            }
            VFS_POSIX_FCNTL => {
                misc::handle_fcntl(state, cli_handle, msg, reply);
            }
            VFS_POSIX_CHDIR => {
                misc::handle_chdir(state, cli_handle, msg, reply);
            }
            VFS_POSIX_GETCWD => {
                misc::handle_getcwd(state, cli_handle, msg, reply);
            }
            VFS_POSIX_TCGETATTR => {
                tty::handle_tcgetattr(state, cli_handle, msg, reply);
            }
            VFS_POSIX_TCSETATTR => {
                tty::handle_tcsetattr(state, cli_handle, msg, reply);
            }
            // *at() family
            VFS_POSIX_OPENAT => {
                skip_reply = at_ops::handle_openat(state, cli_handle, msg, reply);
            }
            VFS_POSIX_FSTATAT => {
                skip_reply = at_ops::handle_fstatat(state, cli_handle, msg, reply);
            }
            VFS_POSIX_UNLINKAT => {
                skip_reply = at_ops::handle_unlinkat(state, cli_handle, msg, reply);
            }
            VFS_POSIX_RENAMEAT => {
                skip_reply = at_ops::handle_renameat(state, cli_handle, msg, reply);
            }
            VFS_POSIX_MKDIRAT => {
                skip_reply = at_ops::handle_mkdirat(state, cli_handle, msg, reply);
            }
            VFS_POSIX_FACCESSAT => {
                skip_reply = at_ops::handle_faccessat(state, cli_handle, msg, reply);
            }
            VFS_POSIX_FCHMODAT => {
                skip_reply = at_ops::handle_fchmodat(state, cli_handle, msg, reply);
            }
            VFS_POSIX_FCHOWNAT => {
                skip_reply = at_ops::handle_fchownat(state, cli_handle, msg, reply);
            }
            VFS_POSIX_LINKAT => {
                skip_reply = at_ops::handle_linkat(state, cli_handle, msg, reply);
            }
            VFS_POSIX_SYMLINKAT => {
                skip_reply = at_ops::handle_symlinkat(state, cli_handle, msg, reply);
            }
            VFS_POSIX_READLINKAT => {
                skip_reply = at_ops::handle_readlinkat(state, cli_handle, msg, reply);
            }
            VFS_POSIX_UTIMENSAT => {
                skip_reply = at_ops::handle_utimensat(state, cli_handle, msg, reply);
            }
            VFS_POSIX_FCHMOD => {
                skip_reply = at_ops::handle_fchmod(state, cli_handle, msg, reply);
            }
            VFS_POSIX_FCHOWN => {
                skip_reply = at_ops::handle_fchown(state, cli_handle, msg, reply);
            }
            // Mount namespace
            VFS_POSIX_UNSHARE => {
                handle_unshare(state, cli_handle, msg, reply);
            }
            _ => return None,
        }
        Some(skip_reply)
    }
}

/// Check if a client's fd has a specific neutral backing kind.
fn is_fd_type(state: &VfsState, cli_handle: ClientHandle, fd: i32, kind: ObjectKind) -> bool {
    if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
        return false;
    }
    state
        .open_object_at(cli_handle, fd as usize)
        .map(|obj| obj.kind() == kind)
        .unwrap_or(false)
}

/// POSIX `unshare(CLONE_NEWNS)` — create a private mount namespace.
unsafe fn handle_unshare(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    const CLONE_NEWNS: u64 = 0x0002_0000;

    unsafe {
        let flags = (*msg).regs[0];
        if (flags & CLONE_NEWNS) == 0 {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return;
        }

        // Clone the current mount namespace.
        let parent_nsh = {
            let cli = match state.clients.get(cli_handle) {
                Some(c) => c,
                None => {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
            };
            if cli.mount_ns.is_valid() {
                cli.mount_ns
            } else {
                state.global_ns
            }
        };

        if !parent_nsh.is_valid() {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            return;
        }

        // Allocate new namespace and copy from parent.
        let new_nsh = match state.mount_ns.alloc() {
            Some(h) => h,
            None => {
                (*reply).label = TRONA_OUT_OF_MEMORY;
                return;
            }
        };

        {
            let parent = match state.mount_ns.get(parent_nsh) {
                Some(ns) => ns,
                None => {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return;
                }
            };
            let mounts_copy = parent.mounts;
            let count = parent.mount_count;
            let root = parent.root_mount;

            let new_ns = match state.mount_ns.get_mut(new_nsh) {
                Some(ns) => ns,
                None => {
                    (*reply).label = TRONA_OUT_OF_MEMORY;
                    return;
                }
            };
            *new_ns = crate::vfs_core::mount_ns::MountNamespace::zeroed();
            new_ns.refcount = 1;
            new_ns.root_mount = root;
            new_ns.mounts = mounts_copy;
            new_ns.mount_count = count;
        }

        // Update client's mount namespace.
        let old_nsh = {
            let cli = match state.clients.get_mut(cli_handle) {
                Some(c) => c,
                None => {
                    (*reply).label = TRONA_INVALID_ARGUMENT;
                    return;
                }
            };
            let old = cli.mount_ns;
            cli.mount_ns = new_nsh;
            old
        };

        // Release old namespace if refcount drops to zero.
        if old_nsh.is_valid() {
            if let Some(old_ns) = state.mount_ns.get_mut(old_nsh) {
                if old_ns.refcount > 0 {
                    old_ns.refcount -= 1;
                }
                if old_ns.refcount == 0 {
                    state.mount_ns.release(old_nsh);
                }
            }
        }

        (*reply).label = TRONA_OK;
    }
}

// =========================================================================
// Object-type-aware I/O dispatch — called from owner dispatch for
// VFS_READ/VFS_WRITE/VFS_CLOSE
// =========================================================================

/// POSIX read dispatch: routes by object type to the appropriate backend.
/// Returns `true` if reply should be skipped (deferred).
pub(crate) unsafe fn dispatch_read(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let kind = state
            .open_object_at(cli_handle, fd as usize)
            .map(|obj| obj.kind())
            .unwrap_or(ObjectKind::None);

        match kind {
            ObjectKind::InetSocket => inet::handle_inet_read(state, cli_handle, fd, msg, reply),
            ObjectKind::UnixSocket => socket::handle_socket_read(state, cli_handle, fd, reply),
            ObjectKind::Pipe => pipe::handle_pipe_read(state, cli_handle, fd, msg, reply),
            ObjectKind::Device => misc::handle_device_read(state, cli_handle, fd, msg, reply),
            _ => crate::fileops::rw::handle_read_owned(state, cli_handle, msg, reply),
        }
    }
}

/// POSIX write dispatch: routes by object type.
pub(crate) unsafe fn dispatch_write(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        if fd < 0 || fd as usize >= MAX_CLIENT_OBJECTS {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        let kind = state
            .open_object_at(cli_handle, fd as usize)
            .map(|obj| obj.kind())
            .unwrap_or(ObjectKind::None);

        match kind {
            ObjectKind::InetSocket => inet::handle_inet_write(state, cli_handle, fd, msg, reply),
            ObjectKind::UnixSocket => {
                socket::handle_socket_write(state, cli_handle, fd, msg, reply)
            }
            ObjectKind::Pipe => pipe::handle_pipe_write(state, cli_handle, fd, msg, reply),
            ObjectKind::Device => misc::handle_device_write(state, cli_handle, fd, msg, reply),
            _ => crate::fileops::rw::handle_write_owned(state, cli_handle, msg, reply),
        }
    }
}

/// POSIX client exit cleanup: walk the exiting client's live slots and
/// route every one through the neutral `close_open_object` so the
/// shared refcount semantics and `release_backing` dispatcher fire
/// exactly like an in-session `close(fd)`.
///
/// `badge` is the exiting client's badge, threaded through from
/// `dispatch_client_exit` so the SHM arm of `release_backing` can issue
/// `MM_SHM_UNMAP` while the mapping is still resolvable.
pub(crate) unsafe fn cleanup_client_objects(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    badge: u64,
) {
    unsafe {
        if state.clients.get(cli_handle).is_none() {
            return;
        }
        for i in 0..MAX_CLIENT_OBJECTS {
            if state.open_object_at(cli_handle, i).is_some() {
                let _ = state.close_open_object(cli_handle, i, badge);
            }
        }
    }
}
