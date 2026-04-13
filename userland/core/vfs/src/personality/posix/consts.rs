// SPDX-License-Identifier: GPL-2.0-only
//! POSIX-specific constants for the VFS server.
//!
//! Extracted from `server/consts.rs` — these encode POSIX inode mode
//! format, POSIX-only object types, BSD socket states, and POSIX-only
//! pool sizing. Neutral code should not import from this module.

// POSIX inode mode type bits (S_IF*)
pub(crate) const S_IFMT_L: u32 = 0o170000;
pub(crate) const S_IFDIR_L: u32 = 0o040000;
pub(crate) const S_IFCHR_L: u32 = 0o020000;
pub(crate) const S_IFREG_L: u32 = 0o100000;
pub(crate) const S_IFSOCK_L: u32 = 0o140000;
pub(crate) const S_IFLNK_L: u32 = 0o120000;

// Shared device subtype for /dev/urandom.
pub(crate) const DEV_URANDOM: u8 = trona::consts::posix::DEV_URANDOM;

// BSD socket states
pub(crate) const SOCK_UNBOUND: u8 = 0;
pub(crate) const SOCK_BOUND: u8 = 1;
pub(crate) const SOCK_LISTENING: u8 = 2;
pub(crate) const SOCK_CONNECTING: u8 = 3;
pub(crate) const SOCK_CONNECTED: u8 = 4;
pub(crate) const SOCK_CLOSED: u8 = 5;

// Socket/poll/shm initial capacities and limits
pub(crate) const INITIAL_SOCKETS: usize = 32;
pub(crate) const SOCK_BUF_SIZE: usize = 4096;
pub(crate) const INITIAL_POLL_WAITERS: usize = 16;
pub(crate) const MAX_SHM_PAGES: usize = 64;
pub(crate) const INITIAL_PENDING_CONN: usize = 4;
pub(crate) const INITIAL_EPOLLS: usize = 8;
pub(crate) const INITIAL_EPOLL_ENTRIES: usize = 16;
pub(crate) const INITIAL_SHM: usize = 8;

// Pipe limits and pool sizes
pub(crate) const PIPE_BUF_SIZE: usize = 4096;
pub(crate) const INITIAL_PIPES: usize = 16;
pub(crate) const INITIAL_PIPE_WAITERS: usize = 4;

// PTY limits
pub(crate) const MAX_PTYS: usize = 4;
pub(crate) const MAX_PTY_WAITERS: usize = 4;

// POSIX AT_* constants (openat/fstatat/etc.)
pub(crate) const AT_FDCWD_VAL: i32 = -100;
pub(crate) const AT_SYMLINK_NOFOLLOW_VAL: i32 = 0x100;
pub(crate) const AT_REMOVEDIR_VAL: i32 = 0x200;
pub(crate) const AT_EMPTY_PATH_VAL: i32 = 0x1000;
