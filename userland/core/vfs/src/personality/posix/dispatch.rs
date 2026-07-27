// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX label-range dispatch entry — `0x500..=0x53F`.
//!
//! Owner-reactor's frontend `kind=0` branch delegates here when
//! the client's [`Personality`] is `Posix`. This module routes
//! the inbound label onto the matching POSIX entry under
//! `personality::posix::*`. Each entry decodes the POSIX wire
//! shape and emits the reply through `personality::reply::*`.
//!
//! No request-decoding logic lives here — that's the entry's
//! job. The dispatcher is a single fan-out match so a malformed
//! label is rejected at one place rather than once per entry.
//!
//! [`Personality`]: super::super::Personality

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::owner::VfsState;
use crate::personality::wire::send_error_reply;
use crate::server::types::ClientHandle;
use trona_protocol::vfs::public::{
    VFS_ACCEPT, VFS_ACCESS, VFS_BIND, VFS_CANON_PATH, VFS_CHDIR, VFS_CHMOD, VFS_CHOWN,
    VFS_CLIENT_EXIT, VFS_CLOSE, VFS_CONNECT, VFS_DUP, VFS_DUP2, VFS_DUP3, VFS_EPOLL_CREATE,
    VFS_EPOLL_CTL, VFS_EPOLL_WAIT, VFS_FACCESSAT, VFS_FCHMOD, VFS_FCHOWN, VFS_FCNTL, VFS_FDATASYNC,
    VFS_FGETXATTR, VFS_FIFO_OPEN, VFS_FLISTXATTR, VFS_FREMOVEXATTR, VFS_FSETXATTR, VFS_FSTAT,
    VFS_FSTATAT, VFS_FSYNC, VFS_FTRUNCATE, VFS_FUTIMES, VFS_GET_BACKING_MO, VFS_GET_CTTY_DEV,
    VFS_GETCWD, VFS_GETDENTS, VFS_GETPEERNAME, VFS_GETSOCKNAME, VFS_GETSOCKOPT, VFS_IOCTL,
    VFS_ISATTY, VFS_LINK, VFS_LISTEN, VFS_LSTAT, VFS_MKDIR, VFS_MKFIFO, VFS_MKNOD, VFS_MOUNT,
    VFS_MOUNT_LIST, VFS_OPEN, VFS_OPEN_FOR_EXEC, VFS_OPENAT, VFS_PIPE, VFS_PIPE2, VFS_POLL,
    VFS_PTY_READY, VFS_READ, VFS_READLINK, VFS_RECV, VFS_REGISTER_BULK_SHM, VFS_RELEASE_BULK_SHM,
    VFS_REMOUNT, VFS_RENAME, VFS_RMDIR, VFS_SEEK, VFS_SEND, VFS_SETSOCKOPT, VFS_SHM_OPEN,
    VFS_SHM_UNLINK, VFS_SHUTDOWN, VFS_SOCKET, VFS_SOCKETPAIR, VFS_STAT, VFS_STAT_FOR_EXEC,
    VFS_STATVFS, VFS_SYMLINK, VFS_TCGETATTR, VFS_TCSETATTR, VFS_TRUNCATE, VFS_UMOUNT, VFS_UNLINK,
    VFS_UTIMES, VFS_WRITE,
};

/// Dispatch a frontend RPC whose label landed in the POSIX
/// range. Caller (the owner-reactor frontend handler) has
/// already resolved `client` from the inbound badge and parked
/// the saved reply lease into a `ReplyLease`.
pub(crate) unsafe fn dispatch(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        match msg.label {
            // -------- File / fd lifecycle --------
            VFS_OPEN | VFS_OPENAT => super::open::handle(state, client, msg, reply_lease),
            VFS_CLOSE => super::close::handle(state, client, msg, reply_lease),
            VFS_CLIENT_EXIT => {
                crate::personality::wire::send_ok_reply(reply_lease, &[]);
                crate::owner::clients::remove_client(state, client);
            }
            VFS_DUP => super::dup::handle_dup(state, client, msg, reply_lease),
            VFS_DUP2 => super::dup::handle_dup2(state, client, msg, reply_lease),
            VFS_DUP3 => super::dup::handle_dup3(state, client, msg, reply_lease),
            VFS_FCNTL => super::fcntl::handle(state, client, msg, reply_lease),
            VFS_IOCTL => super::ioctl::handle(state, client, msg, reply_lease),
            VFS_GET_CTTY_DEV => super::device::handle_get_ctty_dev(state, client, msg, reply_lease),

            // -------- I/O --------
            VFS_READ => super::io::handle_read(state, client, msg, reply_lease),
            VFS_WRITE => super::io::handle_write(state, client, msg, reply_lease),
            VFS_SEEK => super::io::handle_seek(state, client, msg, reply_lease),
            VFS_FSYNC | VFS_FDATASYNC => super::io::handle_fsync(state, client, msg, reply_lease),
            VFS_FTRUNCATE => super::io::handle_ftruncate(state, client, msg, reply_lease),
            VFS_TRUNCATE => super::setattr::handle_truncate(state, client, msg, reply_lease),

            // -------- Metadata --------
            VFS_STAT | VFS_LSTAT | VFS_FSTAT | VFS_FSTATAT => {
                super::stat::handle(state, client, msg, reply_lease)
            }
            VFS_STATVFS => super::mount::handle_statvfs(state, client, msg, reply_lease),
            VFS_ACCESS | VFS_FACCESSAT => super::access::handle(state, client, msg, reply_lease),
            VFS_CHMOD => super::setattr::handle_chmod(state, client, msg, reply_lease),
            VFS_FCHMOD => super::setattr::handle_fchmod(state, client, msg, reply_lease),
            VFS_CHOWN => super::setattr::handle_chown(state, client, msg, reply_lease),
            VFS_FCHOWN => super::setattr::handle_fchown(state, client, msg, reply_lease),
            VFS_UTIMES => super::setattr::handle_utimes(state, client, msg, reply_lease),
            VFS_FUTIMES => super::setattr::handle_futimes(state, client, msg, reply_lease),
            VFS_READLINK => super::readlink::handle(state, client, msg, reply_lease),
            VFS_GETDENTS => super::dir::handle(state, client, msg, reply_lease),
            VFS_FGETXATTR => super::xattr::handle_fgetxattr(state, client, msg, reply_lease),
            VFS_FLISTXATTR => super::xattr::handle_flistxattr(state, client, msg, reply_lease),
            VFS_FSETXATTR => super::xattr::handle_fsetxattr(state, client, msg, reply_lease),
            VFS_FREMOVEXATTR => super::xattr::handle_fremovexattr(state, client, msg, reply_lease),

            // -------- Directory mutations --------
            VFS_UNLINK => super::unlink::handle_unlink(state, client, msg, reply_lease),
            VFS_RMDIR => super::unlink::handle_rmdir(state, client, msg, reply_lease),
            VFS_LINK => super::link::handle(state, client, msg, reply_lease),
            VFS_RENAME => super::rename::handle(state, client, msg, reply_lease),
            VFS_MKDIR => super::mkdir::handle(state, client, msg, reply_lease),
            VFS_SYMLINK => super::symlink::handle(state, client, msg, reply_lease),

            // -------- Mount table --------
            VFS_MOUNT => super::mount::handle_mount(state, client, msg, reply_lease),
            VFS_UMOUNT => super::mount::handle_umount(state, client, msg, reply_lease),
            VFS_REMOUNT => super::mount::handle_remount(state, client, msg, reply_lease),
            VFS_MOUNT_LIST => super::mountlist::handle(state, client, msg, reply_lease),

            // -------- POSIX-only extensions (0x5C0-0x5DF) --------
            VFS_CHDIR => super::cwd::handle_chdir(state, client, msg, reply_lease),
            VFS_GETCWD => super::cwd::handle_getcwd(state, client, msg, reply_lease),
            VFS_STAT_FOR_EXEC => {
                super::exec_helpers::handle_stat_for_exec(state, client, msg, reply_lease)
            }
            VFS_OPEN_FOR_EXEC => {
                super::exec_helpers::handle_open_for_exec(state, client, msg, reply_lease)
            }
            VFS_CANON_PATH => {
                super::exec_helpers::handle_canon_path(state, client, msg, reply_lease)
            }
            VFS_MKFIFO => super::mkfifo::handle(state, client, msg, reply_lease),
            VFS_MKNOD => super::mknod::handle(state, client, msg, reply_lease),
            VFS_ISATTY => super::tty::handle_isatty(state, client, msg, reply_lease),
            VFS_TCGETATTR => super::tty::handle_tcgetattr(state, client, msg, reply_lease),
            VFS_TCSETATTR => super::tty::handle_tcsetattr(state, client, msg, reply_lease),
            VFS_PTY_READY => super::tty::handle_pty_ready(state, client, msg, reply_lease),

            // -------- mmap / SHM --------
            VFS_GET_BACKING_MO => super::mmap::handle(state, client, msg, reply_lease),
            VFS_SHM_OPEN | VFS_SHM_UNLINK => super::shm::handle(state, client, msg, reply_lease),
            VFS_REGISTER_BULK_SHM => {
                super::bulk_shm::handle_register(state, client, msg, reply_lease)
            }
            VFS_RELEASE_BULK_SHM => {
                super::bulk_shm::handle_release(state, client, msg, reply_lease)
            }

            // -------- Poll / epoll --------
            VFS_POLL => super::poll::handle(state, client, msg, reply_lease),
            VFS_EPOLL_CREATE | VFS_EPOLL_CTL | VFS_EPOLL_WAIT => {
                super::epoll::handle(state, client, msg, reply_lease)
            }

            // -------- Pipes / FIFOs --------
            VFS_PIPE | VFS_PIPE2 => super::pipe::handle(state, client, msg, reply_lease),
            VFS_FIFO_OPEN => super::fifo::handle(state, client, msg, reply_lease),

            // -------- Sockets --------
            //
            // `super::socket::handle` owns the entire POSIX family
            // and routes to the per-AF backing path internally.
            VFS_SOCKET | VFS_SOCKETPAIR | VFS_BIND | VFS_LISTEN | VFS_ACCEPT | VFS_CONNECT
            | VFS_SHUTDOWN | VFS_SEND | VFS_RECV | VFS_GETSOCKNAME | VFS_GETPEERNAME
            | VFS_SETSOCKOPT | VFS_GETSOCKOPT => {
                super::socket::handle(state, client, msg, reply_lease)
            }

            // -------- Unknown POSIX label --------
            _ => send_error_reply(reply_lease, VfsError::NotSup),
        }
    }
}
