// SPDX-License-Identifier: GPL-2.0-only
//! VFS protocol constants, file types, and configuration values.

// Cap layout (VFS-specific — different from trona::consts well-known slots)
pub(crate) const CAP_SELF_TCB: u64 = 0;
pub(crate) const CAP_SELF_VSPACE: u64 = 1;
pub(crate) const CAP_SELF_CSPACE: u64 = 2;
pub(crate) const CAP_SERVER_EP: u64 = 3;
pub(crate) const CAP_INITRD_UNTYPED: u64 = 12;
pub(crate) const CAP_READINESS_NTFN: u64 = 14;
pub(crate) const VFS_CAP_CONSOLE_EP: u64 = 64; // NeedEP console:64
pub(crate) const VFS_CAP_NAMESRV_EP: u64 = 65; // NeedEP namesrv:65
pub(crate) const VFS_CAP_POSIX_TTYSRV_EP: u64 = 67; // NeedEP posix_ttysrv:67
pub(crate) const VFS_CAP_FB_UNTYPED: u64 = 66; // CopyCap 13:66
pub(crate) const VFS_CAP_PTY_NTFN: u64 = 68; // CopyCap 14:68 (PTY data-ready notification)
pub(crate) const VFS_CAP_MMSRV_EP: u64 = 69; // NeedEP mmsrv:69
pub(crate) const VFS_CAP_PROCMGR_EP: u64 = 70; // NeedEP procmgr:70
pub(crate) const VFS_CAP_NETSRV_EP: u64 = 71; // NeedEP netsrv:71
pub(crate) const NETSRV_CALLBACK_BADGE: u64 = 0x4E37D;

// ObjectEntry.rights bitmask (set at open time, capability-based access control)
pub(crate) const OBJ_RIGHT_READ: u8 = 1 << 0;
pub(crate) const OBJ_RIGHT_WRITE: u8 = 1 << 1;

// ObjectEntry.flags internal bits. Status flags remain in the low POSIX range.
pub(crate) const OBJ_FLAG_CLOEXEC: u32 = 1 << 31;

// VFS protocol labels — canonical definitions in trona::consts (uapi/protocol/vfs.rs)

/// Per-client bulk SHM size (1MB = 256 pages).
pub(crate) const CLIENT_BULK_SHM_PAGES: u64 = 256;

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
pub(crate) const PROC_FILE_NET_DIR: u8 = 6; // /proc/net
pub(crate) const PROC_FILE_NET_ROUTE: u8 = 7; // /proc/net/route
pub(crate) const PROC_FILE_NET_ARP: u8 = 8; // /proc/net/arp
pub(crate) const PROC_FILE_NET_DEV: u8 = 9; // /proc/net/dev
pub(crate) const PROC_FILE_ETC_HOSTS: u8 = 10; // /etc/hosts and /etc/host
pub(crate) const PROC_FILE_ETC_RESOLV_CONF: u8 = 11; // /etc/resolv.conf

// Open flags — use trona::consts::O_* (POSIX u32)

// Inode mode flags
pub(crate) const S_IFMT_L: u32 = 0o170000;
pub(crate) const S_IFDIR_L: u32 = 0o040000;
pub(crate) const S_IFCHR_L: u32 = 0o020000;
pub(crate) const S_IFREG_L: u32 = 0o100000;
pub(crate) const S_IFSOCK_L: u32 = 0o140000;
pub(crate) const S_IFLNK_L: u32 = 0o120000;

// Device types — DEV_CONSOLE/DEV_NULL/DEV_ZERO/DEV_FB0/DEV_PTY_SLAVE from POSIX UAPI
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

// Object types
pub(crate) const OBJ_TYPE_NONE: u8 = 0;
pub(crate) const OBJ_TYPE_DEVICE: u8 = 1;
pub(crate) const OBJ_TYPE_FILE: u8 = 2;
pub(crate) const OBJ_TYPE_DIR: u8 = 3;
pub(crate) const OBJ_TYPE_SOCKET: u8 = 4;
pub(crate) const OBJ_TYPE_SHM: u8 = 5;
pub(crate) const OBJ_TYPE_PIPE: u8 = 7;
pub(crate) const OBJ_TYPE_EPOLL: u8 = 8;
pub(crate) const OBJ_TYPE_MOUNT: u8 = 9;
pub(crate) const OBJ_TYPE_INET_SOCKET: u8 = 10;

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
pub(crate) const CAP_REPLY_LIMIT: u64 = 62;
pub(crate) const VFS_CAP_NETSRV_CALLBACK_EP: u64 = 63; // bootstrap-private callback EP injected by init

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
pub(crate) const VFS_SALTYFS_SHM_PAGES: u64 = 256; // 1MB
pub(crate) const VFS_SALTYFS_SHM_ID: u64 = 0x56534653; // "VSFS"
pub(crate) const VFS_FILE_MMAP_SCRATCH_VADDR: u64 = 0x0000_0000_7000_0000;

// PTY pending reader queue for deferred terminal reads
pub(crate) const MAX_PTYS: usize = 4;
pub(crate) const MAX_PTY_WAITERS: usize = 4;
