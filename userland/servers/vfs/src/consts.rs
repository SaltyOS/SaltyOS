// SPDX-License-Identifier: GPL-2.0-only
//! VFS protocol constants, file types, and configuration values.

// Cap layout (VFS-specific — different from besalt::consts well-known slots)
pub(crate) const CAP_SELF_TCB: u64 = 0;
pub(crate) const CAP_SELF_VSPACE: u64 = 1;
pub(crate) const CAP_SELF_CSPACE: u64 = 2;
pub(crate) const CAP_SERVER_EP: u64 = 3;
pub(crate) const CAP_INITRD_UNTYPED: u64 = 12;
pub(crate) const CAP_READINESS_NTFN: u64 = 14;
pub(crate) const VFS_CAP_CONSOLE_EP: u64 = 64; // NeedEP console:64
pub(crate) const VFS_CAP_NAMESERV_EP: u64 = 65; // NeedEP nameserv:65
pub(crate) const VFS_CAP_TTYD_EP: u64 = 67; // NeedEP ttyd:67
pub(crate) const VFS_CAP_FB_UNTYPED: u64 = 66; // CopyCap 13:66
pub(crate) const VFS_CAP_PTY_NTFN: u64 = 68; // CopyCap 14:68 (PTY data-ready notification)
pub(crate) const VFS_CAP_MMSRV_EP: u64 = 69; // NeedEP mmsrv:69
pub(crate) const VFS_CAP_PROCMGR_EP: u64 = 70; // NeedEP procmgr:70
pub(crate) const VFS_CAP_NETSRV_EP: u64 = 71; // NeedEP netsrv:71
pub(crate) const VFS_CAP_NETSRV_CALLBACK_EP: u64 = 72; // badged copy of server EP for netsrv callbacks
pub(crate) const NETSRV_CALLBACK_BADGE: u64 = 0x4E37D;
pub(crate) const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

// VFS protocol labels
pub(crate) const VFS_OPEN: u64 = 1;
pub(crate) const VFS_READ: u64 = 2;
pub(crate) const VFS_WRITE: u64 = 3;
pub(crate) const VFS_CLOSE: u64 = 4;
pub(crate) const VFS_STAT: u64 = 5;
pub(crate) const VFS_LSEEK: u64 = 6;
pub(crate) const VFS_FSTAT: u64 = 7;
pub(crate) const VFS_ACCESS: u64 = 8;
pub(crate) const VFS_UNLINK: u64 = 9;
pub(crate) const VFS_RENAME: u64 = 10;
pub(crate) const VFS_MKDIR: u64 = 11;
pub(crate) const VFS_RMDIR: u64 = 12;
pub(crate) const VFS_OPENDIR: u64 = 13;
pub(crate) const VFS_READDIR: u64 = 14;
pub(crate) const VFS_LSTAT: u64 = 15;
pub(crate) const VFS_POLL: u64 = 16;
pub(crate) const VFS_SHM_OPEN: u64 = 17;
pub(crate) const VFS_SHM_UNLINK: u64 = 18;
pub(crate) const VFS_FTRUNCATE: u64 = 19;
pub(crate) const VFS_SOCKET: u64 = 20;
pub(crate) const VFS_BIND: u64 = 21;
pub(crate) const VFS_LISTEN: u64 = 22;
pub(crate) const VFS_ACCEPT: u64 = 23;
pub(crate) const VFS_CONNECT: u64 = 24;
pub(crate) const VFS_SENDMSG: u64 = 25;
pub(crate) const VFS_RECVMSG: u64 = 26;
pub(crate) const VFS_SOCKPAIR: u64 = 27;
pub(crate) const VFS_SHUTDOWN: u64 = 28;
pub(crate) const VFS_PIPE: u64 = 29;
pub(crate) const VFS_DUP: u64 = 30;
pub(crate) const VFS_DUP2: u64 = 31;
pub(crate) const VFS_CLONE_FDS: u64 = 32;
pub(crate) const VFS_IOCTL: u64 = 33;
pub(crate) const VFS_ISATTY: u64 = 34;
pub(crate) const VFS_FCNTL: u64 = 35;
pub(crate) const VFS_CHDIR: u64 = 36;
pub(crate) const VFS_GETCWD: u64 = 37;
pub(crate) const VFS_TCGETATTR: u64 = 38;
pub(crate) const VFS_TCSETATTR: u64 = 39;
pub(crate) const VFS_EPOLL_CREATE: u64 = 40;
pub(crate) const VFS_EPOLL_CTL: u64 = 41;
pub(crate) const VFS_EPOLL_WAIT: u64 = 42;
pub(crate) const VFS_DUP3: u64 = 43;
pub(crate) const VFS_MKFIFO: u64 = 44;
pub(crate) const VFS_MMAP: u64 = 45;
pub(crate) const VFS_MUNMAP: u64 = 46;
pub(crate) const VFS_OPENAT: u64 = 47;
pub(crate) const VFS_FSTATAT: u64 = 48;
pub(crate) const VFS_UNLINKAT: u64 = 49;
pub(crate) const VFS_RENAMEAT: u64 = 50;
pub(crate) const VFS_MKDIRAT: u64 = 51;
pub(crate) const VFS_FACCESSAT: u64 = 52;
pub(crate) const VFS_FCHMODAT: u64 = 53;
pub(crate) const VFS_FCHOWNAT: u64 = 54;
pub(crate) const VFS_LINKAT: u64 = 55;
pub(crate) const VFS_SYMLINKAT: u64 = 56;
pub(crate) const VFS_READLINKAT: u64 = 57;
pub(crate) const VFS_UTIMENSAT: u64 = 58;
pub(crate) const VFS_FCHMOD: u64 = 59;
pub(crate) const VFS_FCHOWN: u64 = 60;
pub(crate) const VFS_CLIENT_EXIT: u64 = 61;
pub(crate) const VFS_PREAD: u64 = 62;
pub(crate) const VFS_PWRITE: u64 = 63;
pub(crate) const VFS_BULK_SETUP: u64 = 64;
pub(crate) const VFS_BULK_READ: u64 = 65;

/// Per-client bulk SHM size (256KB = 64 pages).
pub(crate) const CLIENT_BULK_SHM_PAGES: u64 = 64;

pub(crate) const TTYD_GET_FG_PGRP: u64 = 1;
pub(crate) const TTYD_SET_FG_PGRP: u64 = 2;
pub(crate) const TTYD_SET_CTTY: u64 = 3;
pub(crate) const TTYD_DROP_CTTY: u64 = 4;
pub(crate) const TTYD_PTY_READ: u64 = 11;
pub(crate) const TTYD_PTY_WRITE: u64 = 12;
pub(crate) const TTYD_PTY_TCGETATTR: u64 = 14;
pub(crate) const TTYD_PTY_TCSETATTR: u64 = 15;
pub(crate) const TTYD_PTY_IOCTL: u64 = 16;
pub(crate) const TTYD_PTY_POLL: u64 = 17;
pub(crate) const TTYD_PTY_COLLECT: u64 = 19;

pub(crate) const AT_FDCWD_VAL: i32 = -100;
pub(crate) const AT_SYMLINK_NOFOLLOW_VAL: i32 = 0x100;
pub(crate) const AT_REMOVEDIR_VAL: i32 = 0x200;
pub(crate) const AT_EMPTY_PATH_VAL: i32 = 0x1000;

// File type constants
pub(crate) const FTYPE_NONE: u8 = 0;
pub(crate) const FTYPE_CHAR_DEVICE: u8 = 1;
pub(crate) const FTYPE_REGULAR: u8 = 2;
pub(crate) const FTYPE_DIRECTORY: u8 = 3;
pub(crate) const FTYPE_SOCKET: u8 = 4;
pub(crate) const FTYPE_SHM: u8 = 5;
pub(crate) const FTYPE_FIFO: u8 = 6;
pub(crate) const FTYPE_SYMLINK: u8 = 7;
pub(crate) const FTYPE_PROC_FILE: u8 = 8;
pub(crate) const FTYPE_MOUNT_POINT: u8 = 9;

// /proc file subtypes (stored in dev_type for FTYPE_PROC_FILE inodes)
pub(crate) const PROC_FILE_STATUS: u8 = 1;
pub(crate) const PROC_FILE_STAT: u8 = 2;
pub(crate) const PROC_FILE_MAPS: u8 = 3;
pub(crate) const PROC_FILE_ROOT: u8 = 4; // /proc directory itself
pub(crate) const PROC_FILE_PID_DIR: u8 = 5; // /proc/<pid> directory

// Open flags — use besalt::consts::O_* (POSIX u32)

// Inode mode flags
pub(crate) const S_IFMT_L: u32 = 0o170000;
pub(crate) const S_IFDIR_L: u32 = 0o040000;
pub(crate) const S_IFCHR_L: u32 = 0o020000;
pub(crate) const S_IFREG_L: u32 = 0o100000;
pub(crate) const S_IFSOCK_L: u32 = 0o140000;
pub(crate) const S_IFLNK_L: u32 = 0o120000;

// Device types — DEV_CONSOLE/DEV_NULL/DEV_ZERO from besalt::consts
pub(crate) const DEV_FB0: u8 = 3;
pub(crate) const DEV_PTY_SLAVE: u8 = 4;
pub(crate) const DEV_URANDOM: u8 = 5;

// Initial capacities (growable pools)
pub(crate) const INITIAL_INODES: usize = 128;
pub(crate) const INITIAL_DIRENTS: usize = 32;
pub(crate) const INITIAL_WRITABLE: usize = 32;
pub(crate) const WRITABLE_SIZE: usize = 8192;
pub(crate) const INITIAL_CLIENTS: usize = 16;
pub(crate) const INITIAL_FDS: usize = 32;
// Semantic limits (not pool sizes)
pub(crate) const MAX_PATH_LEN: usize = 128;
pub(crate) const MAX_NAME_LEN: usize = 255;

// FD types
pub(crate) const FD_TYPE_NONE: u8 = 0;
pub(crate) const FD_TYPE_DEVICE: u8 = 1;
pub(crate) const FD_TYPE_FILE: u8 = 2;
pub(crate) const FD_TYPE_DIR: u8 = 3;
pub(crate) const FD_TYPE_SOCKET: u8 = 4;
pub(crate) const FD_TYPE_SHM: u8 = 5;
pub(crate) const FD_TYPE_PIPE: u8 = 7;
pub(crate) const FD_TYPE_EPOLL: u8 = 8;
pub(crate) const FD_TYPE_MOUNT: u8 = 9;
pub(crate) const FD_TYPE_INET_SOCKET: u8 = 10;

// Socket states
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
pub(crate) const MAX_SHM_PAGES: usize = 64; // Per-SHM limit (semantic)
pub(crate) const INITIAL_PENDING_CONN: usize = 4;

// Cap slot range for deferred replies.
// Keep this strictly below 64 so it never collides with service-injected caps
// (NeedEP/CopyCap are validated to use slots >= 64) or rtld runtime slot pool.
pub(crate) const CAP_REPLY_BASE: u64 = 32;
pub(crate) const CAP_REPLY_LIMIT: u64 = 63;

// Root inode
pub(crate) const ROOT_INO: u32 = 1;

pub(crate) const INITRD_VADDR: u64 = 0x0000_0000_0100_0000;

pub(crate) const MOUNT_READDIR_BATCH_MAX: usize = 3;

pub(crate) const INITIAL_EPOLLS: usize = 8;
pub(crate) const INITIAL_EPOLL_ENTRIES: usize = 16;

pub(crate) const INITIAL_SHM: usize = 8;

pub(crate) const PIPE_BUF_SIZE: usize = 4096;
pub(crate) const INITIAL_PIPES: usize = 16;
pub(crate) const INITIAL_PIPE_WAITERS: usize = 4;

pub(crate) const INITIAL_SYMLINKS: usize = 32;

pub(crate) const MAX_MOUNTS: usize = 4;

/// VFS-SaltyFS shared memory for bulk data transport
pub(crate) const VFS_SALTYFS_SHM_VADDR: u64 = 0x0000_0000_5000_0000;
pub(crate) const VFS_SALTYFS_SHM_PAGES: u64 = 64; // 256KB
pub(crate) const VFS_SALTYFS_SHM_ID: u64 = 0x56534653; // "VSFS"

// PTY pending reader queue for deferred terminal reads
pub(crate) const MAX_PTYS: usize = 4;
pub(crate) const MAX_PTY_WAITERS: usize = 4;
