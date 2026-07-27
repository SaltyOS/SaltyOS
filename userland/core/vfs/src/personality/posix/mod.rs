// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX personality. Owns the POSIX wire types (struct stat,
//! dirent layout, sigset, sockaddr_*, pollfd) and the namei rules
//! (case-sensitive UTF-8, `.` / `..` semantics, symlink hop count
//! 40, no leading drive letter).
//!
//! Filesystems that present a Linux-style ABI to userspace see the
//! world through this module. The vnode core stays personality-
//! neutral so the same node is also reachable from `personality/win32`.

pub(crate) mod access;
pub(crate) mod bulk_shm;
pub(crate) mod close;
pub(crate) mod consts;
pub(crate) mod cwd;
pub(crate) mod device;
pub(crate) mod dir;
pub(crate) mod dispatch;
pub(crate) mod dup;
pub(crate) mod epoll;
pub(crate) mod exec_helpers;
pub(crate) mod fcntl;
pub(crate) mod fifo;
pub(crate) mod file;
pub(crate) mod fork_clone;
pub(crate) mod inet;
pub(crate) mod inet_wait;
pub(crate) mod io;
pub(crate) mod ioctl;
pub(crate) mod link;
pub(crate) mod mkdir;
pub(crate) mod mkfifo;
pub(crate) mod mknod;
pub(crate) mod mmap;
pub(crate) mod mount;
pub(crate) mod mountlist;
pub(crate) mod namei;
pub(crate) mod open;
pub(crate) mod pipe;
pub(crate) mod poll;
pub(crate) mod readlink;
pub(crate) mod rename;
pub(crate) mod reply;
pub(crate) mod scm_rights;
pub(crate) mod setattr;
pub(crate) mod shm;
pub(crate) mod signals;
pub(crate) mod socket;
pub(crate) mod socket_wait;
pub(crate) mod stat;
pub(crate) mod symlink;
pub(crate) mod tty;
pub(crate) mod types;
pub(crate) mod unlink;
pub(crate) mod wire;
pub(crate) mod xattr;
