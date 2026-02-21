//! SaltyOS VFS Server
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Virtual filesystem with ramfs (in-memory filesystem) and devfs.
//! Mounts initrd CPIO as read-only /initrd/. Device files at /dev/.
//!
//! IPC protocol:
//!   Label  1 = OPEN     Label  8 = ACCESS
//!   Label  2 = READ     Label  9 = UNLINK
//!   Label  3 = WRITE    Label 10 = RENAME
//!   Label  4 = CLOSE    Label 11 = MKDIR
//!   Label  5 = STAT     Label 12 = RMDIR
//!   Label  6 = LSEEK    Label 13 = OPENDIR
//!   Label  7 = FSTAT    Label 14 = READDIR
//!                        Label 15 = LSTAT
//!
//! Cap layout (set by init/procmgr):
//!   0 = self TCB    4 = console EP
//!   1 = self VSpace 8 = nameserv EP
//!   2 = self CSpace
//!   3 = server endpoint

#![no_std]
#![no_main]

extern crate salty;

use salty::consts::*;
use salty::cpio;
use salty::ipc;
use salty::serial;
use salty::serial::LineBuf;
use salty::types::*;

// ======================================================================
// Cap layout (VFS-specific — different from salty::consts well-known slots)
// ======================================================================

const CAP_SELF_TCB: u64 = 0;
const CAP_SELF_VSPACE: u64 = 1;
const CAP_SELF_CSPACE: u64 = 2;
const CAP_SERVER_EP: u64 = 3;
const CAP_INITRD_UNTYPED: u64 = 12;
const CAP_READINESS_NTFN: u64 = 14;
const VFS_CAP_CONSOLE_EP: u64 = 64;    // NeedEP console:64
const VFS_CAP_NAMESERV_EP: u64 = 65;   // NeedEP nameserv:65
const VFS_CAP_TTYD_EP: u64 = 67;       // NeedEP ttyd:67
const VFS_CAP_FB_UNTYPED: u64 = 66;    // CopyCap 13:66
const VFS_CAP_PTY_NTFN: u64 = 68;     // CopyCap 14:68 (PTY data-ready notification)
const VFS_CAP_MMSRV_EP: u64 = 69;     // NeedEP mmsrv:69
const VFS_CAP_PROCMGR_EP: u64 = 70;   // NeedEP procmgr:70
const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

// VFS protocol labels
const VFS_OPEN: u64 = 1;
const VFS_READ: u64 = 2;
const VFS_WRITE: u64 = 3;
const VFS_CLOSE: u64 = 4;
const VFS_STAT: u64 = 5;
const VFS_LSEEK: u64 = 6;
const VFS_FSTAT: u64 = 7;
const VFS_ACCESS: u64 = 8;
const VFS_UNLINK: u64 = 9;
const VFS_RENAME: u64 = 10;
const VFS_MKDIR: u64 = 11;
const VFS_RMDIR: u64 = 12;
const VFS_OPENDIR: u64 = 13;
const VFS_READDIR: u64 = 14;
const VFS_LSTAT: u64 = 15;
const VFS_POLL: u64 = 16;
const VFS_SHM_OPEN: u64 = 17;
const VFS_SHM_UNLINK: u64 = 18;
const VFS_FTRUNCATE: u64 = 19;
const VFS_SOCKET: u64 = 20;
const VFS_BIND: u64 = 21;
const VFS_LISTEN: u64 = 22;
const VFS_ACCEPT: u64 = 23;
const VFS_CONNECT: u64 = 24;
const VFS_SENDMSG: u64 = 25;
const VFS_RECVMSG: u64 = 26;
const VFS_SOCKPAIR: u64 = 27;
const VFS_SHUTDOWN: u64 = 28;
const VFS_IOCTL: u64 = 33;
const VFS_ISATTY: u64 = 34;
const VFS_FCNTL: u64 = 35;
const VFS_CHDIR: u64 = 36;
const VFS_GETCWD: u64 = 37;
const VFS_TCGETATTR: u64 = 38;
const VFS_TCSETATTR: u64 = 39;
const VFS_EPOLL_CREATE: u64 = 40;
const VFS_EPOLL_CTL: u64 = 41;
const VFS_EPOLL_WAIT: u64 = 42;
const VFS_DUP3: u64 = 43;
const VFS_MKFIFO: u64 = 44;
const VFS_MMAP: u64 = 45;
const VFS_MUNMAP: u64 = 46;
const VFS_OPENAT: u64 = 47;
const VFS_FSTATAT: u64 = 48;
const VFS_UNLINKAT: u64 = 49;
const VFS_RENAMEAT: u64 = 50;
const VFS_MKDIRAT: u64 = 51;
const VFS_FACCESSAT: u64 = 52;
const VFS_FCHMODAT: u64 = 53;
const VFS_FCHOWNAT: u64 = 54;
const VFS_LINKAT: u64 = 55;
const VFS_SYMLINKAT: u64 = 56;
const VFS_READLINKAT: u64 = 57;
const VFS_UTIMENSAT: u64 = 58;
const VFS_FCHMOD: u64 = 59;
const VFS_FCHOWN: u64 = 60;
const VFS_CLIENT_EXIT: u64 = 61;

const TTYD_GET_FG_PGRP: u64 = 1;
const TTYD_SET_FG_PGRP: u64 = 2;
const TTYD_SET_CTTY: u64 = 3;
const TTYD_DROP_CTTY: u64 = 4;
const TTYD_PTY_READ: u64 = 11;
const TTYD_PTY_WRITE: u64 = 12;
const TTYD_PTY_TCGETATTR: u64 = 14;
const TTYD_PTY_TCSETATTR: u64 = 15;
const TTYD_PTY_IOCTL: u64 = 16;
const TTYD_PTY_POLL: u64 = 17;
const TTYD_PTY_COLLECT: u64 = 19;

const AT_FDCWD_VAL: i32 = -100;
const AT_REMOVEDIR_VAL: i32 = 0x200;
const AT_EMPTY_PATH_VAL: i32 = 0x1000;

// File type constants
const FTYPE_NONE: u8 = 0;
const FTYPE_CHAR_DEVICE: u8 = 1;
const FTYPE_REGULAR: u8 = 2;
const FTYPE_DIRECTORY: u8 = 3;
const FTYPE_SOCKET: u8 = 4;
const FTYPE_SHM: u8 = 5;
const FTYPE_FIFO: u8 = 6;
const FTYPE_SYMLINK: u8 = 7;
const FTYPE_PROC_FILE: u8 = 8;
const FTYPE_MOUNT_POINT: u8 = 9;

// /proc file subtypes (stored in dev_type for FTYPE_PROC_FILE inodes)
const PROC_FILE_STATUS: u8 = 1;
const PROC_FILE_STAT: u8 = 2;
const PROC_FILE_MAPS: u8 = 3;
const PROC_FILE_ROOT: u8 = 4;  // /proc directory itself
const PROC_FILE_PID_DIR: u8 = 5; // /proc/<pid> directory

// Open flags
const O_ACCMODE: u32 = 0x0003;
const O_WRONLY: u32 = 0x0001;
const O_RDWR: u32 = 0x0002;
const O_CREAT: u32 = 0x0040;
const O_EXCL: u32 = 0x0080;
const O_TRUNC: u32 = 0x0200;
const O_APPEND: u32 = 0x0400;

// Inode mode flags
const S_IFMT_L: u32 = 0o170000;
const S_IFDIR_L: u32 = 0o040000;
const S_IFCHR_L: u32 = 0o020000;
const S_IFREG_L: u32 = 0o100000;
const S_IFSOCK_L: u32 = 0o140000;
const S_IFLNK_L: u32 = 0o120000;

// Device types
const DEV_CONSOLE: u8 = 0;
const DEV_NULL: u8 = 1;
const DEV_ZERO: u8 = 2;
const DEV_FB0: u8 = 3;
const DEV_PTY_SLAVE: u8 = 4;
const DEV_URANDOM: u8 = 5;

// Initial capacities (growable pools)
const INITIAL_INODES: usize = 128;
const INITIAL_DIRENTS: usize = 32;
const INITIAL_WRITABLE: usize = 32;
const WRITABLE_SIZE: usize = 8192;
const INITIAL_CLIENTS: usize = 16;
const INITIAL_FDS: usize = 32;
// Semantic limits (not pool sizes)
const MAX_PATH_LEN: usize = 128;
const MAX_NAME_LEN: usize = 255;

// FD types
const FD_TYPE_NONE: u8 = 0;
const FD_TYPE_DEVICE: u8 = 1;
const FD_TYPE_FILE: u8 = 2;
const FD_TYPE_DIR: u8 = 3;
const FD_TYPE_SOCKET: u8 = 4;
const FD_TYPE_SHM: u8 = 5;

// Socket states
const SOCK_UNBOUND: u8 = 0;
const SOCK_BOUND: u8 = 1;
const SOCK_LISTENING: u8 = 2;
const SOCK_CONNECTING: u8 = 3;
const SOCK_CONNECTED: u8 = 4;
const SOCK_CLOSED: u8 = 5;

// Socket/poll/shm initial capacities and limits
const INITIAL_SOCKETS: usize = 32;
const SOCK_BUF_SIZE: usize = 4096;
const INITIAL_POLL_WAITERS: usize = 16;
const MAX_SHM_PAGES: usize = 64;  // Per-SHM limit (semantic)
const INITIAL_PENDING_CONN: usize = 4;

// Cap slot range for deferred replies.
// Keep this strictly below 64 so it never collides with service-injected caps
// (NeedEP/CopyCap are validated to use slots >= 64) or rtld runtime slot pool.
const CAP_REPLY_BASE: u64 = 32;
const CAP_REPLY_LIMIT: u64 = 63;

// Root inode
const ROOT_INO: u32 = 1;

const INITRD_VADDR: u64 = 0x0000_0000_0100_0000;

fn read_boot_info_initrd_size() -> usize {
    unsafe {
        let page = BOOTINFO_VADDR as *const u64;
        let magic = core::ptr::read_volatile(page);
        if magic != BOOTINFO_MAGIC {
            return 0;
        }
        core::ptr::read_volatile(page.add(2)) as usize
    }
}

#[inline]
fn max_inodes() -> usize { unsafe { *(&raw const INODES_CAP) } }
#[inline]
fn max_writable() -> usize { unsafe { *(&raw const WRITABLE_CAP) } }
#[inline]
fn max_clients() -> usize { unsafe { *(&raw const CLIENTS_CAP) } }
#[inline]
fn max_sockets() -> usize { unsafe { *(&raw const SOCKETS_CAP) } }
#[inline]
fn max_poll_waiters() -> usize { unsafe { *(&raw const POLL_WAITERS_CAP) } }
#[inline]
fn max_epoll_instances() -> usize { unsafe { *(&raw const EPOLLS_CAP) } }
#[inline]
fn max_shm_objects() -> usize { unsafe { *(&raw const SHM_CAP) } }
#[inline]
fn max_shm_pages() -> usize { MAX_SHM_PAGES }
#[inline]
fn max_pipes() -> usize { unsafe { *(&raw const PIPES_CAP) } }

// ======================================================================
// Data structures
// ======================================================================

#[repr(C)]
#[derive(Clone, Copy)]
struct RamfsDirent {
    active: u8,
    ino: u32,
    name: [u8; MAX_NAME_LEN],
    name_len: u8,
}

impl RamfsDirent {
    const fn zeroed() -> Self {
        RamfsDirent {
            active: 0,
            ino: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
        }
    }
}

#[repr(C)]
struct RamfsInode {
    active: u8,
    readonly: u8,
    ino: u32,
    mode: u32,
    nlink: u32,
    size: u64,
    mtime: u32,
    parent_ino: u32,
    ftype: u8,
    dev_type: u8,
    dirents: *mut RamfsDirent,
    dirents_cap: u16,
    ro_data: *const u8,
    rw_data: *mut u8,
    open_count: u32,
}

impl RamfsInode {
    const fn zeroed() -> Self {
        RamfsInode {
            active: 0,
            readonly: 0,
            ino: 0,
            mode: 0,
            nlink: 0,
            size: 0,
            mtime: 0,
            parent_ino: 0,
            ftype: FTYPE_NONE,
            dev_type: 0,
            dirents: core::ptr::null_mut(),
            dirents_cap: 0,
            ro_data: core::ptr::null(),
            rw_data: core::ptr::null_mut(),
            open_count: 0,
        }
    }
}

unsafe impl Sync for RamfsInode {}

const MOUNT_READDIR_BATCH_MAX: usize = 4;

#[repr(C)]
#[derive(Clone, Copy)]
struct MountReaddirEntry {
    ino: u64,
    d_type: u8,
    name_len: u8,
    name: [u8; 16],
}

impl MountReaddirEntry {
    const fn zeroed() -> Self {
        MountReaddirEntry {
            ino: 0,
            d_type: 0,
            name_len: 0,
            name: [0; 16],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FdEntry {
    active: u8,
    fd_type: u8,
    inode: u32,
    offset: u64,
    dir_cursor: u32,
    dev_type: u8,
    flags: u32,
    sock_id: u32,
    mount_batch_count: u8,
    mount_batch_index: u8,
    mount_batch_next_cursor: u32,
    mount_batch: [MountReaddirEntry; MOUNT_READDIR_BATCH_MAX],
}

impl FdEntry {
    const fn zeroed() -> Self {
        FdEntry {
            active: 0,
            fd_type: FD_TYPE_NONE,
            inode: 0,
            offset: 0,
            dir_cursor: 0,
            dev_type: 0,
            flags: 0,
            sock_id: 0,
            mount_batch_count: 0,
            mount_batch_index: 0,
            mount_batch_next_cursor: 0,
            mount_batch: [MountReaddirEntry::zeroed(); MOUNT_READDIR_BATCH_MAX],
        }
    }

    /// Get pipe_id (aliases sock_id for pipe FDs)
    fn pipe_id(&self) -> u32 {
        self.sock_id
    }
}

#[repr(C)]
struct ClientState {
    badge: u64,
    active: u8,
    fds: *mut FdEntry,
    fds_cap: u16,
    cwd: [u8; 128],
    fd_flags: *mut u8,
}

impl ClientState {
    const fn zeroed() -> Self {
        ClientState {
            badge: 0,
            active: 0,
            fds: core::ptr::null_mut(),
            fds_cap: 0,
            cwd: [0; 128],
            fd_flags: core::ptr::null_mut(),
        }
    }
}

// ======================================================================
// Global state
// ======================================================================

static mut INODES_PTR: *mut RamfsInode = core::ptr::null_mut();
static mut INODES_CAP: usize = 0;
static mut NEXT_INO: u32 = 1;

static mut WRITABLE_POOL_PTR: *mut [u8; WRITABLE_SIZE] = core::ptr::null_mut();
static mut WRITABLE_USED_PTR: *mut u8 = core::ptr::null_mut();
static mut WRITABLE_NEXT_PTR: *mut u32 = core::ptr::null_mut();
static mut WRITABLE_CAP: usize = 0;

// Symlink target pool: each slot holds a target path of up to MAX_PATH_LEN bytes
const INITIAL_SYMLINKS: usize = 32;
static mut SYMLINK_POOL_PTR: *mut [u8; MAX_PATH_LEN] = core::ptr::null_mut();
static mut SYMLINK_USED_PTR: *mut u8 = core::ptr::null_mut();
static mut SYMLINK_CAP: usize = 0;

static mut CLIENTS_PTR: *mut ClientState = core::ptr::null_mut();
static mut CLIENTS_CAP: usize = 0;

// Framebuffer info (read from bootinfo)
static mut FB_WIDTH: u32 = 0;
static mut FB_HEIGHT: u32 = 0;
static mut FB_PITCH: u32 = 0;
static mut FB_BPP: u8 = 0;
static mut FB_RED_POS: u8 = 0;
static mut FB_RED_SIZE: u8 = 0;
static mut FB_GREEN_POS: u8 = 0;
static mut FB_GREEN_SIZE: u8 = 0;
static mut FB_BLUE_POS: u8 = 0;
static mut FB_BLUE_SIZE: u8 = 0;
static mut FB_MMAP_BADGE: u64 = 0;

macro_rules! INODES {
    () => {
        unsafe { core::slice::from_raw_parts_mut(INODES_PTR, max_inodes()) }
    };
}
macro_rules! WRITABLE_POOL {
    () => {
        unsafe { core::slice::from_raw_parts_mut(WRITABLE_POOL_PTR, max_writable()) }
    };
}
macro_rules! WRITABLE_USED {
    () => {
        unsafe { core::slice::from_raw_parts_mut(WRITABLE_USED_PTR, max_writable()) }
    };
}
macro_rules! CLIENTS {
    () => {
        unsafe { core::slice::from_raw_parts_mut(CLIENTS_PTR, max_clients()) }
    };
}

// ======================================================================
// Socket data structures
// ======================================================================

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingConn {
    active: u8,
    client_badge: u64,
    sock_id: u32,
    reply_slot: u64,
}

impl PendingConn {
    const fn zeroed() -> Self {
        PendingConn { active: 0, client_badge: 0, sock_id: 0, reply_slot: 0 }
    }
}

#[repr(C)]
struct SocketState {
    active: u8,
    state: u8,
    sock_id: u32,
    bound_ino: u32,
    backlog: u8,
    pending_count: u8,
    pending: *mut PendingConn,
    pending_cap: u8,
    peer_sock_id: u32,
    peer_badge: u64,
    data_buf: [u8; SOCK_BUF_SIZE],
    data_head: u16,
    data_tail: u16,
    accept_reply_slot: u64,
    accept_badge: u64,
    recv_reply_slot: u64,
    recv_badge: u64,
    pending_caps: [u64; 4],
    pending_cap_count: u8,
    shut_rd: u8,
    shut_wr: u8,
    peer_closed: u8,
    refcount: u16,
}

impl SocketState {
    const fn zeroed() -> Self {
        SocketState {
            active: 0, state: SOCK_UNBOUND, sock_id: 0, bound_ino: 0,
            backlog: 0, pending_count: 0,
            pending: core::ptr::null_mut(), pending_cap: 0,
            peer_sock_id: 0, peer_badge: 0,
            data_buf: [0; SOCK_BUF_SIZE],
            data_head: 0, data_tail: 0,
            accept_reply_slot: 0, accept_badge: 0,
            recv_reply_slot: 0, recv_badge: 0,
            pending_caps: [0; 4], pending_cap_count: 0,
            shut_rd: 0, shut_wr: 0, peer_closed: 0,
            refcount: 0,
        }
    }
}

unsafe impl Sync for SocketState {}

static mut SOCKETS_PTR: *mut SocketState = core::ptr::null_mut();
static mut SOCKETS_CAP: usize = 0;
static mut NEXT_SOCK_ID: u32 = 1;

macro_rules! SOCKETS {
    () => {
        unsafe { core::slice::from_raw_parts_mut(SOCKETS_PTR, max_sockets()) }
    };
}

// ======================================================================
// Poll data structures
// ======================================================================

#[repr(C)]
struct PollWaiter {
    active: u8,
    badge: u64,
    reply_slot: u64,
    fds: [(i32, u16); 8],
    nfds: u8,
}

impl PollWaiter {
    const fn zeroed() -> Self {
        PollWaiter {
            active: 0, badge: 0, reply_slot: 0,
            fds: [(-1, 0); 8], nfds: 0,
        }
    }
}

static mut POLL_WAITERS_PTR: *mut PollWaiter = core::ptr::null_mut();
static mut POLL_WAITERS_CAP: usize = 0;

macro_rules! POLL_WAITERS {
    () => {
        unsafe { core::slice::from_raw_parts_mut(POLL_WAITERS_PTR, max_poll_waiters()) }
    };
}

// ======================================================================
// Epoll data structures
// ======================================================================

const INITIAL_EPOLLS: usize = 8;
const INITIAL_EPOLL_ENTRIES: usize = 16;

struct EpollEntry {
    active: u8,
    fd: i32,
    events: u32,
    data: u64,
}

impl EpollEntry {
    const fn zeroed() -> Self {
        EpollEntry { active: 0, fd: -1, events: 0, data: 0 }
    }
}

struct EpollInstance {
    active: u8,
    owner_badge: u64,
    entries: *mut EpollEntry,
    entries_cap: u16,
}

impl EpollInstance {
    const fn zeroed() -> Self {
        EpollInstance {
            active: 0,
            owner_badge: 0,
            entries: core::ptr::null_mut(),
            entries_cap: 0,
        }
    }
}

static mut EPOLLS_PTR: *mut EpollInstance = core::ptr::null_mut();
static mut EPOLLS_CAP: usize = 0;

macro_rules! EPOLLS {
    () => {
        unsafe { core::slice::from_raw_parts_mut(EPOLLS_PTR, max_epoll_instances()) }
    };
}

// ======================================================================
// SHM data structures
// ======================================================================

#[repr(C)]
struct ShmData {
    active: u8,
    num_pages: u16,
}

impl ShmData {
    const fn zeroed() -> Self {
        ShmData { active: 0, num_pages: 0 }
    }
}

unsafe impl Sync for ShmData {}

const INITIAL_SHM: usize = 8;
static mut SHM_DATA_PTR: *mut ShmData = core::ptr::null_mut();
static mut SHM_CAP: usize = 0;

macro_rules! SHM_DATA {
    () => {
        unsafe { core::slice::from_raw_parts_mut(SHM_DATA_PTR, max_shm_objects()) }
    };
}

// ======================================================================
// Pipe data structures
// ======================================================================

const PIPE_BUF_SIZE: usize = 4096;
const INITIAL_PIPES: usize = 16;
const FD_TYPE_PIPE: u8 = 7;
const FD_TYPE_EPOLL: u8 = 8;
const FD_TYPE_MOUNT: u8 = 9;
const INITIAL_PIPE_WAITERS: usize = 4;

const VFS_PIPE: u64 = 29;
const VFS_DUP: u64 = 30;
const VFS_DUP2: u64 = 31;
const VFS_CLONE_FDS: u64 = 32;

#[repr(C)]
#[derive(Clone, Copy)]
struct PipeReadWaiter {
    reply_slot: u64,
    badge: u64,
    requested_len: u16,
}

impl PipeReadWaiter {
    const fn zeroed() -> Self {
        PipeReadWaiter { reply_slot: 0, badge: 0, requested_len: 0 }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PipeWriteWaiter {
    reply_slot: u64,
    badge: u64,
    data: [u8; 144],
    data_len: u16,
}

impl PipeWriteWaiter {
    const fn zeroed() -> Self {
        PipeWriteWaiter { reply_slot: 0, badge: 0, data: [0; 144], data_len: 0 }
    }
}

#[repr(C)]
struct PipeState {
    active: u8,
    pipe_id: u32,
    read_refcount: u16,
    write_refcount: u16,
    data_buf: [u8; PIPE_BUF_SIZE],
    data_head: u16,
    data_tail: u16,
    recv_waiters: *mut PipeReadWaiter,
    recv_waiter_cap: u8,
    recv_waiter_count: u8,
    write_waiters: *mut PipeWriteWaiter,
    write_waiter_cap: u8,
    write_waiter_count: u8,
}

impl PipeState {
    const fn zeroed() -> Self {
        PipeState {
            active: 0,
            pipe_id: 0,
            read_refcount: 0,
            write_refcount: 0,
            data_buf: [0; PIPE_BUF_SIZE],
            data_head: 0,
            data_tail: 0,
            recv_waiters: core::ptr::null_mut(),
            recv_waiter_cap: 0,
            recv_waiter_count: 0,
            write_waiters: core::ptr::null_mut(),
            write_waiter_cap: 0,
            write_waiter_count: 0,
        }
    }
}

unsafe impl Sync for PipeState {}

static mut PIPES_PTR: *mut PipeState = core::ptr::null_mut();
static mut PIPES_CAP: usize = 0;
static mut NEXT_PIPE_ID: u32 = 1;

macro_rules! PIPES {
    () => {
        unsafe { core::slice::from_raw_parts_mut(PIPES_PTR, max_pipes()) }
    };
}

// PTY pending reader queue for deferred terminal reads
const MAX_PTYS: usize = 4;
const MAX_PTY_WAITERS: usize = 4;

#[derive(Clone, Copy)]
struct PtyPendingReader {
    active: u8,
    badge: u64,
    reply_slot: u64,
    max_count: u64,
}

impl PtyPendingReader {
    const fn zeroed() -> Self {
        PtyPendingReader { active: 0, badge: 0, reply_slot: 0, max_count: 0 }
    }
}

static mut PTY_PENDING: [[PtyPendingReader; MAX_PTY_WAITERS]; MAX_PTYS] =
    [[PtyPendingReader::zeroed(); MAX_PTY_WAITERS]; MAX_PTYS];
static mut PTY_PENDING_COUNT: [usize; MAX_PTYS] = [0; MAX_PTYS];

// Reply slot counter for deferred replies
static mut NEXT_REPLY_SLOT: u64 = CAP_REPLY_BASE;

/// Grow a pool with hybrid strategy: exact fit + minimum growth.
/// Returns 0 on success, -1 on failure.
/// `item_size` is size_of::<T>().
/// `ptr_loc` and `cap_loc` are raw pointers to the globals.
/// `min_required` is the minimum capacity needed (0 = just grow by policy).
/// VFS is single-threaded, so safe to grow without locks.
unsafe fn vfs_grow_pool_with_min(
    ptr_loc: *mut *mut u8,
    cap_loc: *mut usize,
    item_size: usize,
    min_required: usize,
) -> i32 {
    let old_ptr = unsafe { *ptr_loc };
    let old_cap = unsafe { *cap_loc };
    if old_cap == 0 {
        return -1;  // Not initialized
    }
    // Hybrid growth: small pools double, medium 1.5x, large +256
    let growth = if old_cap < 128 {
        old_cap  // 2x for small pools
    } else if old_cap < 1024 {
        old_cap / 2  // 1.5x for medium pools
    } else {
        256  // +256 for large pools
    };
    let new_cap = core::cmp::max(min_required, old_cap + growth);
    let new_bytes = match new_cap.checked_mul(item_size) {
        Some(b) if b > 0 => b,
        _ => return -1,
    };
    let new_pages = (new_bytes + 4095) / 4096;
    let new_ptr = unsafe {
        salty::posix_mm::posix_mmap(
            core::ptr::null_mut(),
            (new_pages * 4096) as u64,
            0x3,  // PROT_READ | PROT_WRITE
            0x22, // MAP_PRIVATE | MAP_ANONYMOUS
            -1, 0,
        )
    };
    if new_ptr.is_null() || new_ptr == usize::MAX as *mut u8 {
        return -1;
    }
    let old_bytes = old_cap * item_size;
    unsafe {
        core::ptr::copy_nonoverlapping(old_ptr, new_ptr, old_bytes);
        core::ptr::write_bytes(new_ptr.add(old_bytes), 0, new_pages * 4096 - old_bytes);
    }
    // Free old allocation
    if !old_ptr.is_null() {
        let old_pages = (old_bytes + 4095) / 4096;
        unsafe {
            salty::posix_mm::posix_munmap(old_ptr, (old_pages * 4096) as u64);
        }
    }
    unsafe {
        *ptr_loc = new_ptr;
        *cap_loc = new_cap;
    }
    0
}

/// Grow a pool with default growth policy (no minimum required).
unsafe fn vfs_grow_pool(
    ptr_loc: *mut *mut u8,
    cap_loc: *mut usize,
    item_size: usize,
) -> i32 {
    vfs_grow_pool_with_min(ptr_loc, cap_loc, item_size, 0)
}


/// Allocate memory for an inner dynamic array via posix_mmap.
unsafe fn vfs_alloc_array<T>(count: usize) -> *mut T {
    unsafe {
        let bytes = core::mem::size_of::<T>()
            .checked_mul(count)
            .unwrap_or(0);
        if bytes == 0 {
            return core::ptr::null_mut();
        }
        let pages = (bytes + 4095) / 4096;
        let ptr = salty::posix_mm::posix_mmap(
            core::ptr::null_mut(),
            (pages * 4096) as u64,
            0x3,  // PROT_READ | PROT_WRITE
            0x22, // MAP_PRIVATE | MAP_ANONYMOUS
            -1,
            0,
        );
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            return core::ptr::null_mut();
        }
        core::ptr::write_bytes(ptr, 0, pages * 4096);
        ptr as *mut T
    }
}

/// Grow an inner array: allocate with hybrid strategy, copy old, munmap old.
/// Returns (new_ptr, new_cap) on success, (null, 0) on failure.
/// `min_required` is the minimum capacity needed (0 = just grow by policy).
unsafe fn vfs_grow_array_with_min<T: Copy>(
    old_ptr: *mut T,
    old_cap: usize,
    min_required: usize,
) -> (*mut T, usize) {
    if old_cap == 0 || old_ptr.is_null() {
        return (core::ptr::null_mut(), 0);
    }
    // Hybrid growth: small 2x, medium 1.5x, large +256
    let growth = if old_cap < 128 {
        old_cap
    } else if old_cap < 1024 {
        old_cap / 2
    } else {
        256
    };
    let new_cap = core::cmp::max(min_required, old_cap + growth);
    let new_ptr = vfs_alloc_array::<T>(new_cap);
    if new_ptr.is_null() {
        return (core::ptr::null_mut(), 0);
    }
    // Copy old entries
    unsafe {
        for i in 0..old_cap {
            *new_ptr.add(i) = *old_ptr.add(i);
        }
    }
    // munmap old
    let old_bytes = old_cap * core::mem::size_of::<T>();
    let old_pages = (old_bytes + 4095) / 4096;
    unsafe {
        salty::posix_mm::posix_munmap(old_ptr as *mut u8, (old_pages * 4096) as u64);
    }
    (new_ptr, new_cap)
}

/// Grow an inner array with default growth policy.
unsafe fn vfs_grow_array<T: Copy>(old_ptr: *mut T, old_cap: usize) -> (*mut T, usize) {
    vfs_grow_array_with_min(old_ptr, old_cap, 0)
}

unsafe fn init_dynamic_state_storage() -> i32 {
    // Helper: allocate a pool via posix_mmap and set ptr + cap globals.
    unsafe fn alloc_pool<T>(
        ptr_loc: *mut *mut T,
        cap_loc: *mut usize,
        initial_count: usize,
    ) -> i32 {
        let bytes = match core::mem::size_of::<T>().checked_mul(initial_count) {
            Some(b) if b > 0 => b,
            _ => return -1,
        };
        let pages = (bytes + 4095) / 4096;
        let ptr = unsafe {
            salty::posix_mm::posix_mmap(
                core::ptr::null_mut(),
                (pages * 4096) as u64,
                0x3,  // PROT_READ | PROT_WRITE
                0x22, // MAP_PRIVATE | MAP_ANONYMOUS
                -1, 0,
            )
        };
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            return -1;
        }
        unsafe {
            core::ptr::write_bytes(ptr, 0, pages * 4096);
            *ptr_loc = ptr as *mut T;
            *cap_loc = initial_count;
        }
        0
    }

    unsafe {
        // Allocate each pool at initial (default) capacity
        if alloc_pool(&raw mut INODES_PTR, &raw mut INODES_CAP, 128) != 0 {
            return SALTY_OUT_OF_MEMORY as i32;
        }
        // WRITABLE needs two parallel arrays
        if alloc_pool(&raw mut WRITABLE_POOL_PTR, &raw mut WRITABLE_CAP, 32) != 0 {
            return SALTY_OUT_OF_MEMORY as i32;
        }
        let writable_used_bytes = 32;  // Same count
        let writable_used_pages = (writable_used_bytes + 4095) / 4096;
        let ptr = salty::posix_mm::posix_mmap(
            core::ptr::null_mut(),
            (writable_used_pages * 4096) as u64,
            0x3, 0x22, -1, 0,
        );
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            return SALTY_OUT_OF_MEMORY as i32;
        }
        core::ptr::write_bytes(ptr, 0, writable_used_pages * 4096);
        WRITABLE_USED_PTR = ptr;
        // Note: WRITABLE_CAP already set above for pool count

        // Allocate WRITABLE_NEXT array (parallel to WRITABLE_USED)
        let next_bytes = 32 * core::mem::size_of::<u32>();
        let next_pages = (next_bytes + 4095) / 4096;
        let next_ptr = salty::posix_mm::posix_mmap(
            core::ptr::null_mut(),
            (next_pages * 4096) as u64,
            0x3, 0x22, -1, 0,
        );
        if next_ptr.is_null() || next_ptr == usize::MAX as *mut u8 {
            return SALTY_OUT_OF_MEMORY as i32;
        }
        // Initialize all NEXT entries to u32::MAX (no chain)
        let next_arr = next_ptr as *mut u32;
        for i in 0..32 {
            *next_arr.add(i) = u32::MAX;
        }
        WRITABLE_NEXT_PTR = next_arr;

        // Allocate symlink pool
        if alloc_pool(&raw mut SYMLINK_POOL_PTR, &raw mut SYMLINK_CAP, INITIAL_SYMLINKS) != 0 {
            return SALTY_OUT_OF_MEMORY as i32;
        }
        let sym_used_pages = (INITIAL_SYMLINKS + 4095) / 4096;
        let sym_used_ptr = salty::posix_mm::posix_mmap(
            core::ptr::null_mut(),
            (sym_used_pages * 4096) as u64,
            0x3, 0x22, -1, 0,
        );
        if sym_used_ptr.is_null() || sym_used_ptr == usize::MAX as *mut u8 {
            return SALTY_OUT_OF_MEMORY as i32;
        }
        core::ptr::write_bytes(sym_used_ptr, 0, sym_used_pages * 4096);
        SYMLINK_USED_PTR = sym_used_ptr;

        if alloc_pool(&raw mut CLIENTS_PTR, &raw mut CLIENTS_CAP, 16) != 0 {
            return SALTY_OUT_OF_MEMORY as i32;
        }
        if alloc_pool(&raw mut SOCKETS_PTR, &raw mut SOCKETS_CAP, 32) != 0 {
            return SALTY_OUT_OF_MEMORY as i32;
        }
        if alloc_pool(&raw mut POLL_WAITERS_PTR, &raw mut POLL_WAITERS_CAP, 16) != 0 {
            return SALTY_OUT_OF_MEMORY as i32;
        }
        if alloc_pool(&raw mut EPOLLS_PTR, &raw mut EPOLLS_CAP, 8) != 0 {
            return SALTY_OUT_OF_MEMORY as i32;
        }
        if alloc_pool(&raw mut SHM_DATA_PTR, &raw mut SHM_CAP, 8) != 0 {
            return SALTY_OUT_OF_MEMORY as i32;
        }
        if alloc_pool(&raw mut PIPES_PTR, &raw mut PIPES_CAP, 16) != 0 {
            return SALTY_OUT_OF_MEMORY as i32;
        }

        let mut lb = LineBuf::new();
        lb.str(b"[VFS] Growable pools initialized: inodes=128 clients=16 sockets=32 pipes=16\n");
        lb.flush();

        0
    }
}

// ======================================================================
// Helper functions
// ======================================================================

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn signal_ready() {
    let _ = salty::syscall::syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

fn ipc_ctx() -> *mut IpcContext {
    &raw mut salty::__salty_ipc_ctx
}

// ======================================================================
// xorshift128+ PRNG for /dev/urandom
// ======================================================================

static mut URANDOM_S0: u64 = 0;
static mut URANDOM_S1: u64 = 0;

/// Inode number of /proc directory root.
static mut PROC_ROOT_INO: u32 = 0;

unsafe fn urandom_init() {
    unsafe {
        // Seed from monotonic clock + RDTSC
        let mut ts = Timespec::zeroed();
        salty::syscall::syscall(SYS_CLOCK_GETTIME, 0, &raw mut ts as u64, 0, 0, 0, 0);
        let tsc_lo: u32;
        let tsc_hi: u32;
        core::arch::asm!("rdtsc", out("eax") tsc_lo, out("edx") tsc_hi);
        let tsc: u64 = (tsc_hi as u64) << 32 | tsc_lo as u64;
        URANDOM_S0 = ts.tv_nsec ^ tsc;
        URANDOM_S1 = ts.tv_sec.wrapping_mul(6364136223846793005).wrapping_add(tsc);
        // Ensure non-zero state
        if URANDOM_S0 == 0 && URANDOM_S1 == 0 {
            URANDOM_S0 = 0x0123456789ABCDEF;
            URANDOM_S1 = 0xFEDCBA9876543210;
        }
    }
}

unsafe fn urandom_next() -> u64 {
    unsafe {
        let mut s1 = URANDOM_S0;
        let s0 = URANDOM_S1;
        let result = s0.wrapping_add(s1);
        URANDOM_S0 = s0;
        s1 ^= s1 << 23;
        URANDOM_S1 = s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26);
        result
    }
}

fn str_equal_raw(a: *const u8, alen: usize, b: *const u8, blen: usize) -> bool {
    if alen != blen {
        return false;
    }
    for i in 0..alen {
        unsafe {
            if *a.add(i) != *b.add(i) {
                return false;
            }
        }
    }
    true
}

unsafe fn inode_by_ino(ino: u32) -> *mut RamfsInode {
    unsafe {
        for i in 0..max_inodes() {
            if INODES!()[i].active != 0 && INODES!()[i].ino == ino {
                return &raw mut INODES!()[i];
            }
        }
        core::ptr::null_mut()
    }
}

unsafe fn alloc_inode() -> *mut RamfsInode {
    unsafe {
        for i in 0..max_inodes() {
            if INODES!()[i].active == 0 {
                let n = &raw mut INODES!()[i];
                (*n).active = 1;
                (*n).ino = NEXT_INO;
                NEXT_INO += 1;
                (*n).readonly = 0;
                (*n).nlink = 1;
                (*n).size = 0;
                (*n).mtime = 0;
                (*n).parent_ino = 0;
                (*n).ro_data = core::ptr::null();
                (*n).rw_data = core::ptr::null_mut();
                (*n).open_count = 0;
                // Allocate dirents array if not yet allocated
                if (*n).dirents.is_null() {
                    let ptr = vfs_alloc_array::<RamfsDirent>(INITIAL_DIRENTS);
                    if ptr.is_null() {
                        (*n).active = 0;
                        return core::ptr::null_mut();
                    }
                    (*n).dirents = ptr;
                    (*n).dirents_cap = INITIAL_DIRENTS as u16;
                }
                for j in 0..(*n).dirents_cap as usize {
                    (*(*n).dirents.add(j)).active = 0;
                }
                return n;
            }
        }
        // No free slot: grow the pool and retry
        if vfs_grow_pool(
            &raw mut INODES_PTR as *mut *mut u8,
            &raw mut INODES_CAP,
            core::mem::size_of::<RamfsInode>(),
        ) != 0 {
            return core::ptr::null_mut();
        }
        alloc_inode()  // Tail-recursive retry
    }
}

unsafe fn alloc_writable() -> *mut u8 {
    unsafe {
        for i in 0..max_writable() {
            if WRITABLE_USED!()[i] == 0 {
                WRITABLE_USED!()[i] = 1;
                *WRITABLE_NEXT_PTR.add(i) = u32::MAX;
                for j in 0..WRITABLE_SIZE {
                    WRITABLE_POOL!()[i][j] = 0;
                }
                return WRITABLE_POOL!()[i].as_mut_ptr();
            }
        }
        // No free slot: grow both arrays and retry
        if grow_writable_pool() != 0 {
            return core::ptr::null_mut();
        }
        alloc_writable()
    }
}

/// Get the slot index for a writable data pointer.
unsafe fn slot_index_of(rw_data: *const u8) -> u32 {
    unsafe {
        let base = WRITABLE_POOL_PTR as *const u8;
        let offset = rw_data as usize - base as usize;
        (offset / WRITABLE_SIZE) as u32
    }
}

/// Free an entire chain of writable slots starting from `rw_data`.
unsafe fn free_chain(rw_data: *const u8) {
    unsafe {
        if rw_data.is_null() {
            return;
        }
        let mut idx = slot_index_of(rw_data);
        while (idx as usize) < max_writable() {
            WRITABLE_USED!()[idx as usize] = 0;
            let next = *WRITABLE_NEXT_PTR.add(idx as usize);
            *WRITABLE_NEXT_PTR.add(idx as usize) = u32::MAX;
            if next == u32::MAX {
                break;
            }
            idx = next;
        }
    }
}

/// Free an inode and its associated storage (chain or symlink target).
unsafe fn free_inode(inode: *mut RamfsInode) {
    unsafe {
        if (*inode).ftype == FTYPE_SYMLINK {
            free_symlink_target((*inode).rw_data);
        } else {
            free_chain((*inode).rw_data);
        }
        (*inode).rw_data = core::ptr::null_mut();
        (*inode).active = 0;
    }
}

/// Increment the open reference count on an inode.
unsafe fn inode_open(ino: u32) {
    unsafe {
        let inode = inode_by_ino(ino);
        if !inode.is_null() {
            (*inode).open_count += 1;
        }
    }
}

/// Decrement the open reference count on an inode.
/// If nlink==0 and open_count drops to 0, free the inode storage.
unsafe fn inode_close(ino: u32) {
    unsafe {
        let inode = inode_by_ino(ino);
        if !inode.is_null() && (*inode).open_count > 0 {
            (*inode).open_count -= 1;
            if (*inode).nlink == 0 && (*inode).open_count == 0 {
                free_inode(inode);
            }
        }
    }
}

/// Read from a chain of writable slots.
/// Returns number of bytes actually read.
unsafe fn chain_read(rw_data: *const u8, offset: u64, dst: *mut u8, count: u64) -> u64 {
    unsafe {
        if rw_data.is_null() || count == 0 {
            return 0;
        }
        let mut slot_idx = slot_index_of(rw_data);
        // Skip slots to reach the right offset
        let mut skip_slots = (offset as usize) / WRITABLE_SIZE;
        while skip_slots > 0 && slot_idx != u32::MAX && (slot_idx as usize) < max_writable() {
            slot_idx = *WRITABLE_NEXT_PTR.add(slot_idx as usize);
            skip_slots -= 1;
        }
        if slot_idx == u32::MAX || (slot_idx as usize) >= max_writable() {
            return 0;
        }
        let mut slot_off = (offset as usize) % WRITABLE_SIZE;
        let mut total: u64 = 0;
        while total < count && slot_idx != u32::MAX && (slot_idx as usize) < max_writable() {
            let avail = WRITABLE_SIZE - slot_off;
            let want = (count - total) as usize;
            let n = if want < avail { want } else { avail };
            let src = WRITABLE_POOL!()[slot_idx as usize].as_ptr().add(slot_off);
            core::ptr::copy_nonoverlapping(src, dst.add(total as usize), n);
            total += n as u64;
            slot_off = 0;
            slot_idx = *WRITABLE_NEXT_PTR.add(slot_idx as usize);
        }
        total
    }
}

/// Write to a chain of writable slots, extending the chain as needed.
/// Returns number of bytes actually written, or 0 on allocation failure.
unsafe fn chain_write(rw_data: *mut u8, offset: u64, src: *const u8, count: u64) -> u64 {
    unsafe {
        if rw_data.is_null() || count == 0 {
            return 0;
        }
        let first_idx = slot_index_of(rw_data);
        // Navigate to the slot containing `offset`, extending if needed
        let target_slot_num = (offset as usize) / WRITABLE_SIZE;
        let mut slot_idx = first_idx;
        for _ in 0..target_slot_num {
            let next = *WRITABLE_NEXT_PTR.add(slot_idx as usize);
            if next == u32::MAX || (next as usize) >= max_writable() {
                // Need to extend
                let new_slot = alloc_writable();
                if new_slot.is_null() {
                    return 0;
                }
                let new_idx = slot_index_of(new_slot);
                *WRITABLE_NEXT_PTR.add(slot_idx as usize) = new_idx;
                slot_idx = new_idx;
            } else {
                slot_idx = next;
            }
        }
        let mut slot_off = (offset as usize) % WRITABLE_SIZE;
        let mut total: u64 = 0;
        while total < count {
            if (slot_idx as usize) >= max_writable() {
                break;
            }
            let avail = WRITABLE_SIZE - slot_off;
            let want = (count - total) as usize;
            let n = if want < avail { want } else { avail };
            let dst_ptr = WRITABLE_POOL!()[slot_idx as usize].as_mut_ptr().add(slot_off);
            core::ptr::copy_nonoverlapping(src.add(total as usize), dst_ptr, n);
            total += n as u64;
            slot_off = 0;
            if total < count {
                let next = *WRITABLE_NEXT_PTR.add(slot_idx as usize);
                if next == u32::MAX || (next as usize) >= max_writable() {
                    let new_slot = alloc_writable();
                    if new_slot.is_null() {
                        break;
                    }
                    let new_idx = slot_index_of(new_slot);
                    *WRITABLE_NEXT_PTR.add(slot_idx as usize) = new_idx;
                    slot_idx = new_idx;
                } else {
                    slot_idx = next;
                }
            }
        }
        total
    }
}

/// Truncate a chain: free slots beyond `new_size` bytes.
unsafe fn chain_truncate(rw_data: *mut u8, new_size: u64) {
    unsafe {
        if rw_data.is_null() {
            return;
        }
        let keep_slots = if new_size == 0 { 1 } else { ((new_size as usize) + WRITABLE_SIZE - 1) / WRITABLE_SIZE };
        let mut slot_idx = slot_index_of(rw_data);
        let mut count = 1usize;
        // Walk to the last slot we want to keep
        while count < keep_slots && slot_idx != u32::MAX && (slot_idx as usize) < max_writable() {
            let next = *WRITABLE_NEXT_PTR.add(slot_idx as usize);
            if next == u32::MAX {
                return; // Chain is already shorter
            }
            slot_idx = next;
            count += 1;
        }
        // Free everything after this slot
        let tail = *WRITABLE_NEXT_PTR.add(slot_idx as usize);
        *WRITABLE_NEXT_PTR.add(slot_idx as usize) = u32::MAX;
        if tail != u32::MAX {
            // Walk and free the tail chain
            let mut idx = tail;
            while idx != u32::MAX && (idx as usize) < max_writable() {
                WRITABLE_USED!()[idx as usize] = 0;
                let next = *WRITABLE_NEXT_PTR.add(idx as usize);
                *WRITABLE_NEXT_PTR.add(idx as usize) = u32::MAX;
                idx = next;
            }
        }
        // Zero out data beyond new_size in the last kept slot
        let off_in_slot = (new_size as usize) % WRITABLE_SIZE;
        if off_in_slot > 0 {
            let p = WRITABLE_POOL!()[slot_idx as usize].as_mut_ptr().add(off_in_slot);
            core::ptr::write_bytes(p, 0, WRITABLE_SIZE - off_in_slot);
        }
    }
}

/// Grow WRITABLE_POOL, WRITABLE_USED, and WRITABLE_NEXT arrays in lock-step.
unsafe fn grow_writable_pool() -> i32 {
    unsafe {
        let old_cap = WRITABLE_CAP;
        if old_cap == 0 {
            return -1;
        }
        let new_cap = old_cap * 2;
        // Grow WRITABLE_POOL
        if vfs_grow_pool(
            &raw mut WRITABLE_POOL_PTR as *mut *mut u8,
            &raw mut WRITABLE_CAP,
            core::mem::size_of::<[u8; WRITABLE_SIZE]>(),
        ) != 0 {
            return -1;
        }
        // Grow WRITABLE_USED (WRITABLE_CAP was updated by vfs_grow_pool above)
        let used_bytes = new_cap;
        let used_pages = (used_bytes + 4095) / 4096;
        let new_used_ptr = salty::posix_mm::posix_mmap(
            core::ptr::null_mut(),
            (used_pages * 4096) as u64,
            0x3, 0x22, -1, 0,
        );
        if new_used_ptr.is_null() || new_used_ptr == usize::MAX as *mut u8 {
            return -1;
        }
        let old_used_ptr = WRITABLE_USED_PTR;
        core::ptr::copy_nonoverlapping(old_used_ptr, new_used_ptr, old_cap);
        core::ptr::write_bytes(new_used_ptr.add(old_cap), 0, new_cap - old_cap);
        if !old_used_ptr.is_null() {
            let old_used_pages = (old_cap + 4095) / 4096;
            salty::posix_mm::posix_munmap(old_used_ptr, (old_used_pages * 4096) as u64);
        }
        WRITABLE_USED_PTR = new_used_ptr;

        // Grow WRITABLE_NEXT
        let next_bytes = new_cap * core::mem::size_of::<u32>();
        let next_pages = (next_bytes + 4095) / 4096;
        let new_next_ptr = salty::posix_mm::posix_mmap(
            core::ptr::null_mut(),
            (next_pages * 4096) as u64,
            0x3, 0x22, -1, 0,
        );
        if new_next_ptr.is_null() || new_next_ptr == usize::MAX as *mut u8 {
            return -1;
        }
        let new_next = new_next_ptr as *mut u32;
        let old_next_ptr = WRITABLE_NEXT_PTR;
        core::ptr::copy_nonoverlapping(old_next_ptr, new_next, old_cap);
        // Initialize new entries to u32::MAX
        for i in old_cap..new_cap {
            *new_next.add(i) = u32::MAX;
        }
        if !old_next_ptr.is_null() {
            let old_next_bytes = old_cap * core::mem::size_of::<u32>();
            let old_next_pages = (old_next_bytes + 4095) / 4096;
            salty::posix_mm::posix_munmap(old_next_ptr as *mut u8, (old_next_pages * 4096) as u64);
        }
        WRITABLE_NEXT_PTR = new_next;
        0
    }
}

/// Allocate a symlink pool slot and store the target path.
/// Returns a pointer to the pool entry, or null on failure.
unsafe fn alloc_symlink_target(target: *const u8, target_len: u8) -> *mut u8 {
    unsafe {
        for i in 0..SYMLINK_CAP {
            if *SYMLINK_USED_PTR.add(i) == 0 {
                *SYMLINK_USED_PTR.add(i) = 1;
                let slot = &raw mut (*SYMLINK_POOL_PTR.add(i));
                let dst = slot as *mut u8;
                core::ptr::write_bytes(dst, 0, MAX_PATH_LEN);
                for j in 0..target_len as usize {
                    *dst.add(j) = *target.add(j);
                }
                return dst;
            }
        }
        core::ptr::null_mut()
    }
}

/// Free a symlink pool slot given the pointer into the pool.
unsafe fn free_symlink_target(ptr: *mut u8) {
    unsafe {
        if ptr.is_null() || SYMLINK_POOL_PTR.is_null() {
            return;
        }
        let base = SYMLINK_POOL_PTR as *mut u8;
        let offset = ptr as usize - base as usize;
        let idx = offset / MAX_PATH_LEN;
        if idx < SYMLINK_CAP {
            *SYMLINK_USED_PTR.add(idx) = 0;
        }
    }
}

unsafe fn dir_add_entry(dir: *mut RamfsInode, name: *const u8, name_len: u8, child_ino: u32) -> i32 {
    unsafe {
        for i in 0..(*dir).dirents_cap as usize {
            if (*(*dir).dirents.add(i)).active == 0 {
                (*(*dir).dirents.add(i)).active = 1;
                (*(*dir).dirents.add(i)).ino = child_ino;
                (*(*dir).dirents.add(i)).name_len = name_len;
                let n = if (name_len as usize) < MAX_NAME_LEN {
                    name_len as usize
                } else {
                    MAX_NAME_LEN
                };
                for j in 0..n {
                    (*(*dir).dirents.add(i)).name[j] = *name.add(j);
                }
                return 0;
            }
        }
        // No free slot: grow dirents array and retry
        let (new_ptr, new_cap) = vfs_grow_array((*dir).dirents, (*dir).dirents_cap as usize);
        if new_ptr.is_null() {
            return -1;
        }
        (*dir).dirents = new_ptr;
        (*dir).dirents_cap = new_cap as u16;
        // Retry: first free slot is at old_cap (now active=0 from zero-init)
        dir_add_entry(dir, name, name_len, child_ino)
    }
}

unsafe fn dir_find_entry(dir: *mut RamfsInode, name: *const u8, name_len: u8) -> *mut RamfsDirent {
    unsafe {
        for i in 0..(*dir).dirents_cap as usize {
            if (*(*dir).dirents.add(i)).active != 0
                && str_equal_raw(
                    (*(*dir).dirents.add(i)).name.as_ptr(),
                    (*(*dir).dirents.add(i)).name_len as usize,
                    name,
                    name_len as usize,
                )
            {
                return (*dir).dirents.add(i);
            }
        }
        core::ptr::null_mut()
    }
}

unsafe fn dir_remove_entry(dir: *mut RamfsInode, name: *const u8, name_len: u8) -> i32 {
    unsafe {
        for i in 0..(*dir).dirents_cap as usize {
            if (*(*dir).dirents.add(i)).active != 0
                && str_equal_raw(
                    (*(*dir).dirents.add(i)).name.as_ptr(),
                    (*(*dir).dirents.add(i)).name_len as usize,
                    name,
                    name_len as usize,
                )
            {
                (*(*dir).dirents.add(i)).active = 0;
                return 0;
            }
        }
        -1
    }
}

unsafe fn ensure_readonly_dir(parent: *mut RamfsInode, name: *const u8, name_len: u8) -> *mut RamfsInode {
    unsafe {
        let existing = dir_find_entry(parent, name, name_len);
        if !existing.is_null() {
            let inode = inode_by_ino((*existing).ino);
            if inode.is_null() || (*inode).ftype != FTYPE_DIRECTORY {
                return core::ptr::null_mut();
            }
            return inode;
        }

        let dir = alloc_inode();
        if dir.is_null() {
            return core::ptr::null_mut();
        }

        (*dir).ftype = FTYPE_DIRECTORY;
        (*dir).mode = S_IFDIR_L | 0o555;
        (*dir).readonly = 1;
        (*dir).nlink = 2;
        (*dir).parent_ino = (*parent).ino;

        if dir_add_entry(parent, name, name_len, (*dir).ino) != 0 {
            (*dir).active = 0;
            return core::ptr::null_mut();
        }
        dir
    }
}

unsafe fn mount_initrd_entry(root: *mut RamfsInode, entry: &CpioEntryExt) -> bool {
    unsafe {
        if root.is_null() || entry.name.is_null() || entry.name_len == 0 {
            return false;
        }

        // Normalize CPIO path:
        // - drop leading '/'
        // - drop leading "./"
        // - strip trailing '/'
        let mut start = 0usize;
        let mut end = entry.name_len;

        while start < end && *entry.name.add(start) == b'/' {
            start += 1;
        }
        while start + 1 < end && *entry.name.add(start) == b'.' && *entry.name.add(start + 1) == b'/' {
            start += 2;
        }
        while end > start && *entry.name.add(end - 1) == b'/' {
            end -= 1;
        }

        if start >= end {
            return true;
        }

        let mut current = root;
        let mut pos = start;

        while pos < end {
            while pos < end && *entry.name.add(pos) == b'/' {
                pos += 1;
            }
            if pos >= end {
                break;
            }

            let comp_start = pos;
            while pos < end && *entry.name.add(pos) != b'/' {
                pos += 1;
            }
            let comp_len = pos - comp_start;
            if comp_len == 0 || comp_len >= MAX_NAME_LEN {
                return false;
            }

            let mut next = pos;
            while next < end && *entry.name.add(next) == b'/' {
                next += 1;
            }
            let is_leaf = next >= end;

            if !is_leaf {
                let dir = ensure_readonly_dir(current, entry.name.add(comp_start), comp_len as u8);
                if dir.is_null() {
                    return false;
                }
                current = dir;
                continue;
            }

            let leaf_name = entry.name.add(comp_start);
            let leaf_len = comp_len as u8;
            let leaf_mode = if entry.mode != 0 { entry.mode } else { S_IFREG_L | 0o444 };
            let leaf_is_dir = (leaf_mode & S_IFMT_L) == S_IFDIR_L;
            let leaf_is_symlink = (leaf_mode & S_IFMT_L) == S_IFLNK_L;

            let existing = dir_find_entry(current, leaf_name, leaf_len);
            if !existing.is_null() {
                let inode = inode_by_ino((*existing).ino);
                if inode.is_null() {
                    return false;
                }
                if leaf_is_dir && (*inode).ftype == FTYPE_DIRECTORY {
                    (*inode).mode = leaf_mode;
                    (*inode).readonly = 1;
                    (*inode).nlink = if entry.nlink != 0 { entry.nlink } else { 2 };
                    (*inode).mtime = entry.mtime;
                    (*inode).parent_ino = (*current).ino;
                    return true;
                }
                if !leaf_is_dir && (*inode).ftype == FTYPE_REGULAR {
                    (*inode).mode = leaf_mode;
                    (*inode).readonly = 1;
                    (*inode).nlink = if entry.nlink != 0 { entry.nlink } else { 1 };
                    (*inode).mtime = entry.mtime;
                    (*inode).size = entry.data_len as u64;
                    (*inode).ro_data = entry.data;
                    (*inode).rw_data = core::ptr::null_mut();
                    (*inode).parent_ino = (*current).ino;
                    return true;
                }
                return false;
            }

            let inode = alloc_inode();
            if inode.is_null() {
                return false;
            }

            (*inode).readonly = 1;
            (*inode).mode = leaf_mode;
            (*inode).mtime = entry.mtime;
            (*inode).parent_ino = (*current).ino;
            (*inode).nlink = if entry.nlink != 0 {
                entry.nlink
            } else if leaf_is_dir {
                2
            } else {
                1
            };

            if leaf_is_dir {
                (*inode).ftype = FTYPE_DIRECTORY;
                (*inode).size = 0;
            } else if leaf_is_symlink {
                (*inode).ftype = FTYPE_SYMLINK;
                (*inode).size = entry.data_len as u64;
                (*inode).ro_data = entry.data;
            } else {
                (*inode).ftype = FTYPE_REGULAR;
                (*inode).size = entry.data_len as u64;
                (*inode).ro_data = entry.data;
            }

            if dir_add_entry(current, leaf_name, leaf_len, (*inode).ino) != 0 {
                (*inode).active = 0;
                return false;
            }
            return true;
        }

        true
    }
}

// ======================================================================
// Path resolution
// ======================================================================

/// Read the symlink target from an inode.
/// For writable symlinks, target is in rw_data (symlink pool).
/// For readonly (CPIO) symlinks, target is in ro_data.
/// Returns the target pointer and length.
unsafe fn symlink_target(inode: *const RamfsInode) -> (*const u8, u8) {
    unsafe {
        if !(*inode).rw_data.is_null() {
            return ((*inode).rw_data as *const u8, (*inode).size as u8);
        }
        if !(*inode).ro_data.is_null() {
            return ((*inode).ro_data, (*inode).size as u8);
        }
        (core::ptr::null(), 0)
    }
}

/// Inner path resolution with symlink following.
/// `follow_final`: if true, follow symlink on the last component.
/// `depth`: recursion depth for cycle detection (max 8).
unsafe fn resolve_path_raw_inner(
    path: *const u8, path_len: u8, follow_final: bool, depth: u8,
) -> *mut RamfsInode {
    unsafe {
        if path_len == 0 || depth > 8 {
            return core::ptr::null_mut();
        }

        let mut current = inode_by_ino(ROOT_INO);
        if current.is_null() {
            return core::ptr::null_mut();
        }

        if path_len == 1 && *path == b'/' {
            return current;
        }

        let mut pos: usize = 0;
        if *path == b'/' {
            pos = 1;
        }

        let plen = path_len as usize;
        while pos < plen {
            if (*current).ftype != FTYPE_DIRECTORY
                && (*current).ftype != FTYPE_MOUNT_POINT
            {
                return core::ptr::null_mut();
            }

            // Mount point with remaining path: return the mount point itself.
            // The caller (handle_open etc.) detects FTYPE_MOUNT_POINT and proxies.
            if (*current).ftype == FTYPE_MOUNT_POINT {
                return current;
            }

            let start = pos;
            while pos < plen && *path.add(pos) != b'/' {
                pos += 1;
            }
            let comp_len = pos - start;
            if comp_len == 0 {
                pos += 1;
                continue;
            }

            if pos < plen && *path.add(pos) == b'/' {
                pos += 1;
            }

            if comp_len == 1 && *path.add(start) == b'.' {
                continue;
            }
            if comp_len == 2 && *path.add(start) == b'.' && *path.add(start + 1) == b'.' {
                current = inode_by_ino((*current).parent_ino);
                if current.is_null() {
                    current = inode_by_ino(ROOT_INO);
                    if current.is_null() {
                        return core::ptr::null_mut();
                    }
                }
                continue;
            }

            let de = dir_find_entry(current, path.add(start), comp_len as u8);
            if de.is_null() {
                return core::ptr::null_mut();
            }

            current = inode_by_ino((*de).ino);
            if current.is_null() {
                return core::ptr::null_mut();
            }

            // Check if this component is a symlink
            if (*current).ftype == FTYPE_SYMLINK {
                let is_last = pos >= plen;
                if is_last && !follow_final {
                    // Return the symlink inode itself (for lstat/readlink)
                    return current;
                }
                // Follow the symlink
                let (target, target_len) = symlink_target(current);
                if target.is_null() || target_len == 0 {
                    return core::ptr::null_mut();
                }
                if pos >= plen {
                    // Last component: just resolve target
                    return resolve_path_raw_inner(target, target_len, true, depth + 1);
                }
                // Not last component: concatenate target + remaining path
                let remaining_len = plen - pos;
                let total = target_len as usize + 1 + remaining_len; // target + "/" + rest
                if total > MAX_PATH_LEN {
                    return core::ptr::null_mut();
                }
                let mut combined = [0u8; MAX_PATH_LEN];
                for i in 0..target_len as usize {
                    combined[i] = *target.add(i);
                }
                combined[target_len as usize] = b'/';
                for i in 0..remaining_len {
                    combined[target_len as usize + 1 + i] = *path.add(pos + i);
                }
                return resolve_path_raw_inner(
                    combined.as_ptr(), total as u8, follow_final, depth + 1,
                );
            }
        }

        current
    }
}

unsafe fn resolve_path_raw(path: *const u8, path_len: u8) -> *mut RamfsInode {
    unsafe { resolve_path_raw_inner(path, path_len, true, 0) }
}

/// Resolve path without following the final symlink component.
unsafe fn resolve_path_raw_nofollow(path: *const u8, path_len: u8) -> *mut RamfsInode {
    unsafe { resolve_path_raw_inner(path, path_len, false, 0) }
}

fn is_initrd_prefixed_path(path: *const u8, path_len: u8) -> bool {
    unsafe {
        const PREFIX: &[u8] = b"/initrd";
        let plen = path_len as usize;
        if plen < PREFIX.len() {
            return false;
        }
        for (i, b) in PREFIX.iter().enumerate() {
            if *path.add(i) != *b {
                return false;
            }
        }
        plen == PREFIX.len() || *path.add(PREFIX.len()) == b'/'
    }
}

fn path_has_component_prefix(path: *const u8, path_len: u8, prefix: &[u8]) -> bool {
    unsafe {
        let plen = path_len as usize;
        if plen < prefix.len() {
            return false;
        }
        for (i, b) in prefix.iter().enumerate() {
            if *path.add(i) != *b {
                return false;
            }
        }
        plen == prefix.len() || *path.add(prefix.len()) == b'/'
    }
}

unsafe fn resolve_path(path: *const u8, path_len: u8) -> *mut RamfsInode {
    unsafe {
        let direct = resolve_path_raw(path, path_len);
        if !direct.is_null() {
            return direct;
        }

        // Root path fallback for immutable initrd command trees.
        // Keep this narrow so writable paths (/tmp, /dev, ...) are not remapped.
        let allow_fallback = path_has_component_prefix(path, path_len, b"/bin")
            || path_has_component_prefix(path, path_len, b"/usr");

        if allow_fallback && !is_initrd_prefixed_path(path, path_len) {
            const PREFIX: &[u8] = b"/initrd";
            let in_len = path_len as usize;
            let out_len = PREFIX.len() + in_len;
            if out_len <= MAX_PATH_LEN {
                let mut prefixed = [0u8; MAX_PATH_LEN];
                for (i, b) in PREFIX.iter().enumerate() {
                    prefixed[i] = *b;
                }
                for i in 0..in_len {
                    prefixed[PREFIX.len() + i] = *path.add(i);
                }
                return resolve_path_raw(prefixed.as_ptr(), out_len as u8);
            }
        }

        core::ptr::null_mut()
    }
}

unsafe fn resolve_parent(
    path: *const u8,
    path_len: u8,
    child_name: &mut *const u8,
    child_len: &mut u8,
) -> *mut RamfsInode {
    unsafe {
        if path_len == 0 {
            return core::ptr::null_mut();
        }

        let plen = path_len as usize;
        let mut last_slash: i32 = -1;
        for i in (0..plen).rev() {
            if *path.add(i) == b'/' {
                last_slash = i as i32;
                break;
            }
        }

        if last_slash < 0 {
            return core::ptr::null_mut();
        }

        let mut parent_buf = [0u8; MAX_PATH_LEN];
        let parent_len: u8;
        if last_slash == 0 {
            parent_buf[0] = b'/';
            parent_len = 1;
        } else {
            parent_len = last_slash as u8;
            for i in 0..parent_len as usize {
                parent_buf[i] = *path.add(i);
            }
        }

        *child_name = path.add(last_slash as usize + 1);
        *child_len = (plen - last_slash as usize - 1) as u8;

        // Strip trailing slash from child name
        while *child_len > 0 && *(*child_name).add(*child_len as usize - 1) == b'/' {
            *child_len -= 1;
        }

        resolve_path(parent_buf.as_ptr(), parent_len)
    }
}

/// Resolve a path starting from a given inode (for *at() semantics).
/// Absolute paths always start from ROOT_INO regardless of start_ino.
/// Empty path returns the start inode itself (for AT_EMPTY_PATH).
unsafe fn resolve_path_from(start_ino: u32, path: *const u8, path_len: u8) -> *mut RamfsInode {
    unsafe {
        if path_len == 0 {
            return inode_by_ino(start_ino);
        }

        // Absolute path always from root
        if *path == b'/' {
            return resolve_path(path, path_len);
        }

        // Relative path from start_ino
        let mut current = inode_by_ino(start_ino);
        if current.is_null() {
            return core::ptr::null_mut();
        }

        let mut pos: usize = 0;
        let plen = path_len as usize;
        while pos < plen {
            if (*current).ftype != FTYPE_DIRECTORY
                && (*current).ftype != FTYPE_MOUNT_POINT
            {
                return core::ptr::null_mut();
            }
            if (*current).ftype == FTYPE_MOUNT_POINT {
                return current;
            }

            let start = pos;
            while pos < plen && *path.add(pos) != b'/' {
                pos += 1;
            }
            let comp_len = pos - start;
            if comp_len == 0 {
                pos += 1;
                continue;
            }

            if pos < plen && *path.add(pos) == b'/' {
                pos += 1;
            }

            // Handle "." — stay at current directory
            if comp_len == 1 && *path.add(start) == b'.' {
                continue;
            }
            // Handle ".." — move to parent
            if comp_len == 2 && *path.add(start) == b'.' && *path.add(start + 1) == b'.' {
                current = inode_by_ino((*current).parent_ino);
                if current.is_null() {
                    current = inode_by_ino(ROOT_INO);
                    if current.is_null() {
                        return core::ptr::null_mut();
                    }
                }
                continue;
            }

            let de = dir_find_entry(current, path.add(start), comp_len as u8);
            if de.is_null() {
                return core::ptr::null_mut();
            }

            current = inode_by_ino((*de).ino);
            if current.is_null() {
                return core::ptr::null_mut();
            }
        }

        current
    }
}

/// Resolve parent directory from a given start inode (for *at() semantics).
/// If path is absolute, delegates to resolve_parent.
/// If path has no slash (pure filename), parent is start_ino.
unsafe fn resolve_parent_from(
    start_ino: u32,
    path: *const u8,
    path_len: u8,
    child_name: &mut *const u8,
    child_len: &mut u8,
) -> *mut RamfsInode {
    unsafe {
        if path_len == 0 {
            return core::ptr::null_mut();
        }

        // Absolute path — delegate to resolve_parent (always from root)
        if *path == b'/' {
            return resolve_parent(path, path_len, child_name, child_len);
        }

        let plen = path_len as usize;

        // Find last slash
        let mut last_slash: i32 = -1;
        for i in (0..plen).rev() {
            if *path.add(i) == b'/' {
                last_slash = i as i32;
                break;
            }
        }

        if last_slash < 0 {
            // No slash — path is just a filename, parent is start_ino
            *child_name = path;
            *child_len = path_len;
            while *child_len > 0 && *(*child_name).add(*child_len as usize - 1) == b'/' {
                *child_len -= 1;
            }
            return inode_by_ino(start_ino);
        }

        // Has a slash — resolve parent portion from start_ino
        let parent_len = last_slash as u8;
        *child_name = path.add(last_slash as usize + 1);
        *child_len = (plen - last_slash as usize - 1) as u8;
        while *child_len > 0 && *(*child_name).add(*child_len as usize - 1) == b'/' {
            *child_len -= 1;
        }

        resolve_path_from(start_ino, path, parent_len)
    }
}

/// Determine the start inode for an *at() call given dirfd and path.
/// Returns 0 on error.
unsafe fn resolve_at_start(badge: u64, dirfd: i32, path: *const u8, path_len: u8) -> u32 {
    unsafe {
        // Absolute path always starts from root
        if path_len > 0 && *path == b'/' {
            return ROOT_INO;
        }

        // AT_FDCWD: use client's cwd
        if dirfd == AT_FDCWD_VAL {
            let cli = get_client(badge);
            if cli.is_null() {
                return 0;
            }
            let mut cwd_len: u8 = 0;
            while (cwd_len as usize) < 128 && (*cli).cwd[cwd_len as usize] != 0 {
                cwd_len += 1;
            }
            if cwd_len == 0 {
                return ROOT_INO;
            }
            let inode = resolve_path((*cli).cwd.as_ptr(), cwd_len);
            if inode.is_null() {
                return ROOT_INO;
            }
            return (*inode).ino;
        }

        // dirfd: look up fd table
        let cli = get_client(badge);
        if cli.is_null() {
            return 0;
        }
        if dirfd < 0 || dirfd >= (*cli).fds_cap as i32 || (*(*cli).fds.add(dirfd as usize)).active == 0 {
            return 0;
        }
        (*(*cli).fds.add(dirfd as usize)).inode
    }
}

// ======================================================================
// Initialization
// ======================================================================

unsafe fn init_fb_info() {
    unsafe {
        let bootinfo = BOOTINFO_VADDR as *const u8;
        let magic = (bootinfo as *const u64).read();
        if magic != BOOTINFO_MAGIC {
            return;
        }
        let p32 = bootinfo.add(32) as *const u32;
        FB_WIDTH = p32.read();
        FB_HEIGHT = p32.add(1).read();
        FB_PITCH = p32.add(2).read();
        FB_BPP = *bootinfo.add(44);
        FB_RED_POS = *bootinfo.add(45);
        FB_RED_SIZE = *bootinfo.add(46);
        FB_GREEN_POS = *bootinfo.add(47);
        FB_GREEN_SIZE = *bootinfo.add(48);
        FB_BLUE_POS = *bootinfo.add(49);
        FB_BLUE_SIZE = *bootinfo.add(50);
    }
}

unsafe fn init_ramfs() {
    unsafe {
        for i in 0..max_inodes() {
            INODES!()[i].active = 0;
        }
        for i in 0..max_writable() {
            WRITABLE_USED!()[i] = 0;
        }

        // Create root directory (ino 1)
        let root = alloc_inode();
        (*root).ftype = FTYPE_DIRECTORY;
        (*root).mode = S_IFDIR_L | 0o755;
        (*root).nlink = 2;

        // Create /dev directory
        let dev_dir = alloc_inode();
        (*dev_dir).ftype = FTYPE_DIRECTORY;
        (*dev_dir).mode = S_IFDIR_L | 0o755;
        (*dev_dir).nlink = 2;
        (*dev_dir).parent_ino = (*root).ino;
        dir_add_entry(root, b"dev".as_ptr(), 3, (*dev_dir).ino);

        // Create /dev/console
        let console = alloc_inode();
        (*console).ftype = FTYPE_CHAR_DEVICE;
        (*console).mode = S_IFCHR_L | 0o666;
        (*console).dev_type = DEV_CONSOLE;
        (*console).parent_ino = (*dev_dir).ino;
        dir_add_entry(dev_dir, b"console".as_ptr(), 7, (*console).ino);

        // Create /dev/null
        let null_dev = alloc_inode();
        (*null_dev).ftype = FTYPE_CHAR_DEVICE;
        (*null_dev).mode = S_IFCHR_L | 0o666;
        (*null_dev).dev_type = DEV_NULL;
        (*null_dev).parent_ino = (*dev_dir).ino;
        dir_add_entry(dev_dir, b"null".as_ptr(), 4, (*null_dev).ino);

        // Create /dev/zero
        let zero_dev = alloc_inode();
        (*zero_dev).ftype = FTYPE_CHAR_DEVICE;
        (*zero_dev).mode = S_IFCHR_L | 0o666;
        (*zero_dev).dev_type = DEV_ZERO;
        (*zero_dev).parent_ino = (*dev_dir).ino;
        dir_add_entry(dev_dir, b"zero".as_ptr(), 4, (*zero_dev).ino);

        // Create /dev/fb0
        let fb0_dev = alloc_inode();
        (*fb0_dev).ftype = FTYPE_CHAR_DEVICE;
        (*fb0_dev).mode = S_IFCHR_L | 0o666;
        (*fb0_dev).dev_type = DEV_FB0;
        (*fb0_dev).parent_ino = (*dev_dir).ino;
        dir_add_entry(dev_dir, b"fb0".as_ptr(), 3, (*fb0_dev).ino);

        // Create /dev/pts directory
        let pts_dir = alloc_inode();
        (*pts_dir).ftype = FTYPE_DIRECTORY;
        (*pts_dir).mode = S_IFDIR_L | 0o755;
        (*pts_dir).nlink = 2;
        (*pts_dir).parent_ino = (*dev_dir).ino;
        dir_add_entry(dev_dir, b"pts".as_ptr(), 3, (*pts_dir).ino);

        // Create /dev/pts/0 — PTY slave device
        let pts0 = alloc_inode();
        (*pts0).ftype = FTYPE_CHAR_DEVICE;
        (*pts0).mode = S_IFCHR_L | 0o666;
        (*pts0).dev_type = DEV_PTY_SLAVE;
        (*pts0).size = 0; // pty_id = 0
        (*pts0).parent_ino = (*pts_dir).ino;
        dir_add_entry(pts_dir, b"0".as_ptr(), 1, (*pts0).ino);

        // Create /dev/tty (resolves to PTY slave for single-terminal system)
        let tty_dev = alloc_inode();
        (*tty_dev).ftype = FTYPE_CHAR_DEVICE;
        (*tty_dev).mode = S_IFCHR_L | 0o666;
        (*tty_dev).dev_type = DEV_PTY_SLAVE;
        (*tty_dev).size = 0; // pty_id = 0
        (*tty_dev).parent_ino = (*dev_dir).ino;
        dir_add_entry(dev_dir, b"tty".as_ptr(), 3, (*tty_dev).ino);

        // Create /dev/urandom
        let urandom_dev = alloc_inode();
        (*urandom_dev).ftype = FTYPE_CHAR_DEVICE;
        (*urandom_dev).mode = S_IFCHR_L | 0o666;
        (*urandom_dev).dev_type = DEV_URANDOM;
        (*urandom_dev).parent_ino = (*dev_dir).ino;
        dir_add_entry(dev_dir, b"urandom".as_ptr(), 7, (*urandom_dev).ino);

        // Create /dev/random (alias for urandom)
        let random_dev = alloc_inode();
        (*random_dev).ftype = FTYPE_CHAR_DEVICE;
        (*random_dev).mode = S_IFCHR_L | 0o666;
        (*random_dev).dev_type = DEV_URANDOM;
        (*random_dev).parent_ino = (*dev_dir).ino;
        dir_add_entry(dev_dir, b"random".as_ptr(), 6, (*random_dev).ino);

        // Create /proc directory (virtual, dynamic content)
        let proc_dir = alloc_inode();
        (*proc_dir).ftype = FTYPE_PROC_FILE;
        (*proc_dir).dev_type = PROC_FILE_ROOT;
        (*proc_dir).mode = S_IFDIR_L | 0o555;
        (*proc_dir).readonly = 1;
        (*proc_dir).nlink = 2;
        (*proc_dir).parent_ino = (*root).ino;
        dir_add_entry(root, b"proc".as_ptr(), 4, (*proc_dir).ino);
        PROC_ROOT_INO = (*proc_dir).ino;

        // Create /mnt directory
        let mnt_dir = alloc_inode();
        (*mnt_dir).ftype = FTYPE_DIRECTORY;
        (*mnt_dir).mode = S_IFDIR_L | 0o755;
        (*mnt_dir).nlink = 2;
        (*mnt_dir).parent_ino = (*root).ino;
        dir_add_entry(root, b"mnt".as_ptr(), 3, (*mnt_dir).ino);

        // Create /mnt/data as mount point directory
        let mnt_data = alloc_inode();
        (*mnt_data).ftype = FTYPE_MOUNT_POINT;
        (*mnt_data).mode = S_IFDIR_L | 0o555;
        (*mnt_data).readonly = 1;
        (*mnt_data).nlink = 2;
        (*mnt_data).parent_ino = (*mnt_dir).ino;
        dir_add_entry(mnt_dir, b"data".as_ptr(), 4, (*mnt_data).ino);
        MOUNT_DATA_INO = (*mnt_data).ino;

        // Create /initrd directory
        let initrd_dir = alloc_inode();
        (*initrd_dir).ftype = FTYPE_DIRECTORY;
        (*initrd_dir).mode = S_IFDIR_L | 0o555;
        (*initrd_dir).readonly = 1;
        (*initrd_dir).nlink = 2;
        (*initrd_dir).parent_ino = (*root).ino;
        dir_add_entry(root, b"initrd".as_ptr(), 6, (*initrd_dir).ino);

        // Mount initrd CPIO
        let initrd = INITRD_VADDR as *const u8;
        let initrd_size = read_boot_info_initrd_size();

        { let mut lb = LineBuf::new(); lb.str(b"[VFS] Initrd size: "); lb.hex(initrd_size as u64); lb.str(b" bytes\n"); lb.flush(); }

        let mut offset: usize = 0;
        let mut entry = CpioEntryExt::zeroed();
        let mut file_count: u32 = 0;

        while cpio::cpio_next_ext(initrd, initrd_size, &raw mut offset, &raw mut entry) != 0 {
            // Skip "."
            if entry.name_len == 1 && *entry.name == b'.' {
                continue;
            }
            if mount_initrd_entry(initrd_dir, &entry) {
                file_count += 1;
            }
        }

        { let mut lb = LineBuf::new(); lb.str(b"[VFS] Mounted "); lb.hex(file_count as u64); lb.str(b" initrd files\n"); lb.flush(); }
    }
}

// ======================================================================
// Client management
// ======================================================================

unsafe fn get_client(badge: u64) -> *mut ClientState {
    unsafe {
        for i in 0..max_clients() {
            if CLIENTS!()[i].active != 0 && CLIENTS!()[i].badge == badge {
                return &raw mut CLIENTS!()[i];
            }
        }
        for i in 0..max_clients() {
            if CLIENTS!()[i].active == 0 {
                CLIENTS!()[i].badge = badge;
                CLIENTS!()[i].active = 1;
                // Allocate fds/fd_flags if not yet allocated
                if CLIENTS!()[i].fds.is_null() {
                    let fds_ptr = vfs_alloc_array::<FdEntry>(INITIAL_FDS);
                    let flags_ptr = vfs_alloc_array::<u8>(INITIAL_FDS);
                    if fds_ptr.is_null() || flags_ptr.is_null() {
                        CLIENTS!()[i].active = 0;
                        return core::ptr::null_mut();
                    }
                    CLIENTS!()[i].fds = fds_ptr;
                    CLIENTS!()[i].fds_cap = INITIAL_FDS as u16;
                    CLIENTS!()[i].fd_flags = flags_ptr;
                }
                for j in 0..CLIENTS!()[i].fds_cap as usize {
                    (*CLIENTS!()[i].fds.add(j)).active = 0;
                    *CLIENTS!()[i].fd_flags.add(j) = 0;
                }
                // Initialize cwd to "/"
                CLIENTS!()[i].cwd[0] = b'/';
                let mut k = 1;
                while k < 128 {
                    CLIENTS!()[i].cwd[k] = 0;
                    k += 1;
                }
                return &raw mut CLIENTS!()[i];
            }
        }
        // No free slot: grow the pool and retry
        if vfs_grow_pool(
            &raw mut CLIENTS_PTR as *mut *mut u8,
            &raw mut CLIENTS_CAP,
            core::mem::size_of::<ClientState>(),
        ) != 0 {
            return core::ptr::null_mut();
        }
        get_client(badge)
    }
}

unsafe fn extract_path(msg: *const SaltyMsg, reg_offset: usize, path: *mut u8) -> u8 {
    unsafe {
        let mut path_len = (*msg).regs[reg_offset] as u8;
        if (path_len as usize) > MAX_PATH_LEN {
            path_len = MAX_PATH_LEN as u8;
        }
        let raw = &(*msg).regs[reg_offset + 1] as *const u64 as *const u8;
        for i in 0..path_len as usize {
            *path.add(i) = *raw.add(i);
        }
        path_len
    }
}

fn flags_allow_read(flags: u32) -> bool {
    (flags & O_ACCMODE) != O_WRONLY
}

fn flags_allow_write(flags: u32) -> bool {
    let mode = flags & O_ACCMODE;
    mode == O_WRONLY || mode == O_RDWR
}

// ======================================================================
// Mount point support
// ======================================================================

const MAX_MOUNTS: usize = 4;

#[derive(Clone, Copy)]
struct MountEntry {
    active: u8,
    mount_ino: u32,    // VFS inode for the mount point directory
    fs_cap: u64,       // Cap slot of mounted FS server endpoint
    root_ino: u32,     // Root inode number in the mounted FS
}

impl MountEntry {
    const fn zeroed() -> Self {
        MountEntry { active: 0, mount_ino: 0, fs_cap: 0, root_ino: 0 }
    }
}

static mut MOUNTS: [MountEntry; MAX_MOUNTS] = [MountEntry::zeroed(); MAX_MOUNTS];
static mut MOUNT_DATA_INO: u32 = 0; // inode number of /mnt/data
static mut MOUNT_TRIED: u8 = 0;     // counter: max 3 attempts for saltyfs mount

/// Check if path starts with "/mnt/data" and return the sub-path within the mount.
/// Returns (is_mount, sub_path_start, sub_path_len).
/// - "/mnt/data" or "/mnt/data/" → exact mount point (sub_path_len=0)
/// - "/mnt/data/foo" → sub_path = "foo"
fn parse_mount_path(path: &[u8], path_len: u8) -> (bool, usize, u8) {
    const PREFIX: &[u8] = b"/mnt/data";
    let plen = path_len as usize;
    if plen < PREFIX.len() {
        return (false, 0, 0);
    }
    for i in 0..PREFIX.len() {
        if path[i] != PREFIX[i] {
            return (false, 0, 0);
        }
    }
    if plen == PREFIX.len() {
        // Exact "/mnt/data"
        return (true, plen, 0);
    }
    if path[PREFIX.len()] != b'/' {
        return (false, 0, 0);
    }
    // "/mnt/data/..."
    let sub_start = PREFIX.len() + 1;
    let sub_len = plen - sub_start;
    (true, sub_start, sub_len as u8)
}

/// Find mount entry for a path. Returns mount index or None.
/// On first access to a mount path, triggers lazy mount discovery via nameserv.
unsafe fn find_mount_for_path(path: &[u8], path_len: u8) -> Option<usize> {
    let (is_mount, _, _) = parse_mount_path(path, path_len);
    if !is_mount {
        return None;
    }
    unsafe {
        let mnt_ino = *(&raw const MOUNT_DATA_INO);
        // Check existing mounts
        for i in 0..MAX_MOUNTS {
            let m = &*(&raw const MOUNTS[i]);
            if m.active != 0 && m.mount_ino == mnt_ino {
                return Some(i);
            }
        }
        // Lazy mount: attempt once if not yet tried
        if *(&raw const MOUNT_TRIED) < 3 {
            setup_saltyfs_mount();
            // Re-check after mount attempt
            for i in 0..MAX_MOUNTS {
                let m = &*(&raw const MOUNTS[i]);
                if m.active != 0 && m.mount_ino == mnt_ino {
                    return Some(i);
                }
            }
        }
    }
    None
}

/// Multi-component lookup within a mounted filesystem.
/// E.g. for sub_path "a/b/c", does LOOKUP(root,"a") then LOOKUP(a_ino,"b") etc.
/// Returns remote inode number, or 0 on failure.
unsafe fn mount_lookup(mount_idx: usize, sub_path: *const u8, sub_path_len: u8) -> u64 {
    unsafe {
        let m = &*(&raw const MOUNTS[mount_idx]);
        let mut current_ino = m.root_ino as u64;

        if sub_path_len == 0 {
            return current_ino;
        }

        let mut pos: usize = 0;
        let plen = sub_path_len as usize;

        while pos < plen {
            // Skip leading slashes
            while pos < plen && *sub_path.add(pos) == b'/' {
                pos += 1;
            }
            if pos >= plen {
                break;
            }

            let start = pos;
            while pos < plen && *sub_path.add(pos) != b'/' {
                pos += 1;
            }
            let comp_len = pos - start;
            if comp_len == 0 {
                continue;
            }
            if comp_len > 24 {
                return 0; // name too long for IPC
            }

            // Send SALTYFS_LOOKUP
            let mut req = SaltyMsg::zeroed();
            req.label = SALTYFS_LOOKUP;
            req.regs[0] = current_ino;
            req.regs[1] = comp_len as u64;
            let name_dst = &raw mut req.regs[2] as *mut u8;
            for i in 0..comp_len {
                *name_dst.add(i) = *sub_path.add(start + i);
            }
            req.length = 2 + ((comp_len as u64) + 7) / 8;

            let mut reply = SaltyMsg::zeroed();
            ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut reply);

            if reply.label != SALTY_OK {
                return 0;
            }
            current_ino = reply.regs[0];
        }

        current_ino
    }
}

/// Get stat info from mounted filesystem for a remote inode.
/// Returns (size, mode, nlink, mtime, is_dir).
unsafe fn mount_stat(mount_idx: usize, remote_ino: u64) -> Option<(u64, u32, u32, u64, bool)> {
    unsafe {
        let m = &*(&raw const MOUNTS[mount_idx]);
        let mut req = SaltyMsg::zeroed();
        req.label = SALTYFS_STAT;
        req.regs[0] = remote_ino;
        req.length = 1;

        let mut reply = SaltyMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut reply);

        if reply.label != SALTY_OK {
            return None;
        }

        let size = reply.regs[1];
        let mode = reply.regs[2] as u32;
        let nlink = reply.regs[3] as u32;
        let mtime = reply.regs[4];
        let is_dir = (mode & S_IFMT_L) == S_IFDIR_L;
        Some((size, mode, nlink, mtime, is_dir))
    }
}

/// Read data inline from mounted filesystem. Returns bytes in IPC registers.
unsafe fn mount_read_inline(
    mount_idx: usize, remote_ino: u64, offset: u64, count: u64,
    reply: *mut SaltyMsg,
) {
    unsafe {
        let m = &*(&raw const MOUNTS[mount_idx]);
        let mut req = SaltyMsg::zeroed();
        req.label = SALTYFS_READ_INLINE;
        req.regs[0] = remote_ino;
        req.regs[1] = offset;
        req.regs[2] = count;
        req.length = 3;

        let mut fs_reply = SaltyMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);

        if fs_reply.label != SALTY_OK {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let bytes_read = fs_reply.regs[0];
        (*reply).label = SALTY_OK;
        (*reply).length = 1 + (bytes_read + 7) / 8;
        (*reply).regs[0] = bytes_read;

        if bytes_read > 0 {
            let src = &fs_reply.regs[1] as *const u64 as *const u8;
            let dst = &raw mut (*reply).regs[1] as *mut u8;
            for i in 0..bytes_read as usize {
                *dst.add(i) = *src.add(i);
            }
        }
    }
}

unsafe fn mount_readdir_emit_cached(fde: *mut FdEntry, reply: *mut SaltyMsg) {
    unsafe {
        let fd = &mut *fde;
        let idx = fd.mount_batch_index as usize;
        let ent = &fd.mount_batch[idx];

        (*reply).label = SALTY_OK;
        (*reply).length = 5 + ((ent.name_len as u64 + 7) / 8);
        (*reply).regs[0] = ent.name_len as u64;
        (*reply).regs[1] = 0; // reserved
        (*reply).regs[2] = ent.ino;
        (*reply).regs[3] = ent.d_type as u64;
        for j in 4..20 {
            (*reply).regs[j] = 0;
        }
        let dst = &raw mut (*reply).regs[4] as *mut u8;
        for j in 0..ent.name_len as usize {
            *dst.add(j) = ent.name[j];
        }

        fd.mount_batch_index = fd.mount_batch_index.saturating_add(1);
        if fd.mount_batch_index >= fd.mount_batch_count {
            fd.mount_batch_index = 0;
            fd.mount_batch_count = 0;
            fd.dir_cursor = if fd.mount_batch_next_cursor == 0 {
                u32::MAX
            } else {
                fd.mount_batch_next_cursor
            };
        }
    }
}

/// Read directory entries from mounted filesystem with per-FD batching.
/// SaltyFS may return multiple entries; VFS returns one entry per call while
/// consuming cached batch entries across subsequent calls.
unsafe fn mount_readdir(
    mount_idx: usize, fde: *mut FdEntry, dir_ino: u64, reply: *mut SaltyMsg,
) {
    unsafe {
        let fd = &mut *fde;

        if fd.dir_cursor == u32::MAX {
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }

        if fd.mount_batch_count > 0 && fd.mount_batch_index < fd.mount_batch_count {
            mount_readdir_emit_cached(fde, reply);
            return;
        }

        let m = &*(&raw const MOUNTS[mount_idx]);
        let mut req = SaltyMsg::zeroed();
        req.label = SALTYFS_READDIR;
        req.regs[0] = dir_ino;
        req.regs[1] = fd.dir_cursor as u64;
        req.length = 2;

        let mut fs_reply = SaltyMsg::zeroed();
        ipc::call_ctx(ipc_ctx(), m.fs_cap, &raw const req, &raw mut fs_reply);

        if fs_reply.label != SALTY_OK {
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            fd.dir_cursor = u32::MAX;
            return;
        }

        // saltyfs readdir format:
        // regs[0]=next_cursor, then groups of 4:
        // (child_ino, dir_type, name_lo, name_hi)
        let next_cursor = fs_reply.regs[0] as u32;
        let num_entries = (fs_reply.length.saturating_sub(1)) / 4;
        if num_entries == 0 {
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            fd.dir_cursor = u32::MAX;
            return;
        }

        let take = core::cmp::min(num_entries as usize, MOUNT_READDIR_BATCH_MAX);
        for n in 0..take {
            let base = 1 + n * 4;
            let child_ino = fs_reply.regs[base];
            let dir_type = fs_reply.regs[base + 1] as u8;
            let name_lo = fs_reply.regs[base + 2];
            let name_hi = fs_reply.regs[base + 3];

            let lo = name_lo.to_le_bytes();
            let hi = name_hi.to_le_bytes();
            let mut name = [0u8; 16];
            for j in 0..8 {
                name[j] = lo[j];
            }
            for j in 0..8 {
                name[8 + j] = hi[j];
            }
            let mut name_len: u8 = 0;
            for b in name.iter() {
                if *b == 0 {
                    break;
                }
                name_len += 1;
            }

            let d_type = match dir_type {
                1 => 8, // DT_REG
                2 => 4, // DT_DIR
                _ => 0, // DT_UNKNOWN
            };

            fd.mount_batch[n].ino = child_ino;
            fd.mount_batch[n].d_type = d_type;
            fd.mount_batch[n].name_len = name_len;
            fd.mount_batch[n].name = name;
        }

        fd.mount_batch_count = take as u8;
        fd.mount_batch_index = 0;
        fd.mount_batch_next_cursor = next_cursor;
        mount_readdir_emit_cached(fde, reply);
    }
}

/// Discover saltyfs endpoint via name service and mount at /mnt/data.
/// Called lazily on first access to /mnt/data path. Non-fatal: if saltyfs
/// is not available, VFS continues without mount.
unsafe fn setup_saltyfs_mount() {
    unsafe {
        *(&raw mut MOUNT_TRIED) += 1;

        let mnt_ino = *(&raw const MOUNT_DATA_INO);
        if mnt_ino == 0 {
            puts(b"[VFS] No /mnt/data inode for mount\n");
            return;
        }

        // Allocate a slot to receive the saltyfs endpoint cap
        let fs_slot = match salty::slot_alloc::slot_alloc() {
            Some(s) => s,
            None => {
                puts(b"[VFS] saltyfs: no slot available\n");
                return;
            }
        };

        // Look up "saltyfs" via nameserv
        ipc::set_receive_slot_ctx(
            ipc_ctx(), CAP_SELF_CSPACE, fs_slot, 16, // 16-bit CNode depth
        );

        let mut ns_req = SaltyMsg::zeroed();
        ns_req.label = POSIX_NS_LOOKUP;
        let name = b"saltyfs";
        ns_req.regs[0] = name.len() as u64;
        ns_req.length = 1 + (name.len() as u64 + 7) / 8;
        let ns_dst = &raw mut ns_req.regs[1] as *mut u8;
        for i in 0..name.len() {
            *ns_dst.add(i) = name[i];
        }

        let mut ns_reply = SaltyMsg::zeroed();
        let err = ipc::call_ctx(
            ipc_ctx(), VFS_CAP_NAMESERV_EP,
            &raw const ns_req, &raw mut ns_reply,
        );

        if err != 0 || ns_reply.label != SALTY_OK {
            puts(b"[VFS] saltyfs not found in nameserv (ok if no data disk)\n");
            return;
        }

        puts(b"[VFS] Found saltyfs endpoint via nameserv\n");

        // Send SALTYFS_MOUNT to saltyfs server
        let mut mnt_req = SaltyMsg::zeroed();
        mnt_req.label = SALTYFS_MOUNT;
        mnt_req.length = 0;

        let mut mnt_reply = SaltyMsg::zeroed();
        let merr = ipc::call_ctx(ipc_ctx(), fs_slot, &raw const mnt_req, &raw mut mnt_reply);

        if merr != 0 || (mnt_reply.label != SALTY_OK && mnt_reply.label != SALTY_ALREADY_EXISTS) {
            {
                let mut lb = LineBuf::new();
                lb.str(b"[VFS] saltyfs mount failed err=");
                lb.hex(merr as u64);
                lb.str(b" label=");
                lb.hex(mnt_reply.label);
                lb.str(b"\n");
                lb.flush();
            }
            return;
        }

        let root_ino = mnt_reply.regs[0] as u32;

        // Register in mount table
        for i in 0..MAX_MOUNTS {
            if (*(&raw const MOUNTS[i])).active == 0 {
                (*(&raw mut MOUNTS[i])).active = 1;
                (*(&raw mut MOUNTS[i])).mount_ino = mnt_ino;
                (*(&raw mut MOUNTS[i])).fs_cap = fs_slot;
                (*(&raw mut MOUNTS[i])).root_ino = root_ino;
                break;
            }
        }

        {
            let mut lb = LineBuf::new();
            lb.str(b"[VFS] Mounted saltyfs at /mnt/data root_ino=");
            lb.hex(root_ino as u64);
            lb.str(b"\n");
            lb.flush();
        }
    }
}

// ======================================================================
// Request handlers
// ======================================================================

unsafe fn handle_open(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let flags = (*msg).regs[1] as u32;
        let raw_len = extract_path(msg, 2, path.as_mut_ptr());

        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let Some((path_ptr, path_len)) = normalize_path_for_client(
            badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };
        let path_slice = core::slice::from_raw_parts(path_ptr, path_len as usize);

        // /proc virtual paths — intercept before resolve
        if path_len >= 6 && *path_ptr == b'/' && *path_ptr.add(1) == b'p' && *path_ptr.add(2) == b'r'
            && *path_ptr.add(3) == b'o' && *path_ptr.add(4) == b'c' && *path_ptr.add(5) == b'/'
        {
            if handle_proc_open(path_ptr, path_len, reply, badge) {
                return;
            }
        }

        // Mount point intercept: paths under /mnt/data/
        if let Some(mount_idx) = find_mount_for_path(path_slice, path_len) {
            let (_, sub_start, sub_len) = parse_mount_path(path_slice, path_len);
            if sub_len > 0 {
                // File within mount — lookup and open
                let remote_ino = mount_lookup(mount_idx, path_ptr.add(sub_start), sub_len);
                if remote_ino == 0 {
                    (*reply).label = SALTY_NOT_FOUND;
                    return;
                }

                // Stat the remote inode for metadata
                let stat = mount_stat(mount_idx, remote_ino);
                let (size, _mode, _nlink, _mtime, is_dir) = match stat {
                    Some(s) => s,
                    None => {
                        (*reply).label = SALTY_NOT_FOUND;
                        return;
                    }
                };

                if is_dir {
                    // Directory open: use handle_opendir-style logic
                    let cli = get_client(badge);
                    if cli.is_null() {
                        (*reply).label = SALTY_OUT_OF_MEMORY;
                        return;
                    }
                    for fd in 0..(*cli).fds_cap as usize {
                        if (*(*cli).fds.add(fd)).active == 0 {
                            (*(*cli).fds.add(fd)).active = 1;
                            (*(*cli).fds.add(fd)).fd_type = FD_TYPE_MOUNT;
                            (*(*cli).fds.add(fd)).inode = MOUNT_DATA_INO;
                            (*(*cli).fds.add(fd)).offset = 0;
                            (*(*cli).fds.add(fd)).dir_cursor = 0;
                            (*(*cli).fds.add(fd)).sock_id = remote_ino as u32;
                            (*(*cli).fds.add(fd)).dev_type = mount_idx as u8;
                            (*(*cli).fds.add(fd)).flags = flags;
                            (*(*cli).fds.add(fd)).mount_batch_count = 0;
                            (*(*cli).fds.add(fd)).mount_batch_index = 0;
                            (*(*cli).fds.add(fd)).mount_batch_next_cursor = 0;
                            (*reply).label = SALTY_OK;
                            (*reply).length = 1;
                            (*reply).regs[0] = fd as u64;
                            return;
                        }
                    }
                    (*reply).label = SALTY_OUT_OF_MEMORY;
                    return;
                }

                // Regular file: read-only
                if flags_allow_write(flags) {
                    (*reply).label = SALTY_INVALID_OPERATION;
                    return;
                }

                let cli = get_client(badge);
                if cli.is_null() {
                    (*reply).label = SALTY_OUT_OF_MEMORY;
                    return;
                }
                for fd in 0..(*cli).fds_cap as usize {
                    if (*(*cli).fds.add(fd)).active == 0 {
                        (*(*cli).fds.add(fd)).active = 1;
                        (*(*cli).fds.add(fd)).fd_type = FD_TYPE_MOUNT;
                        (*(*cli).fds.add(fd)).inode = MOUNT_DATA_INO;
                        (*(*cli).fds.add(fd)).offset = 0;
                        (*(*cli).fds.add(fd)).dir_cursor = 0;
                        (*(*cli).fds.add(fd)).sock_id = remote_ino as u32;
                        (*(*cli).fds.add(fd)).dev_type = mount_idx as u8;
                        (*(*cli).fds.add(fd)).flags = flags;
                        (*(*cli).fds.add(fd)).mount_batch_count = 0;
                        (*(*cli).fds.add(fd)).mount_batch_index = 0;
                        (*(*cli).fds.add(fd)).mount_batch_next_cursor = 0;
                        (*reply).label = SALTY_OK;
                        (*reply).length = 1;
                        (*reply).regs[0] = fd as u64;
                        return;
                    }
                }
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }
            // Exact "/mnt/data" — falls through to resolve_path (it's a local dir)
        }

        let mut inode = resolve_path(path_ptr, path_len);

        if inode.is_null() {
            if (flags & O_CREAT) == 0 {
                (*reply).label = SALTY_NOT_FOUND;
                return;
            }

            let mut child_name: *const u8 = core::ptr::null();
            let mut child_len: u8 = 0;
            let parent = resolve_parent(path_ptr, path_len, &mut child_name, &mut child_len);
            if !parent.is_null()
                && (*parent).ftype == FTYPE_DIRECTORY
                && (*parent).readonly == 0
                && child_len > 0
            {
                inode = alloc_inode();
                if !inode.is_null() {
                    (*inode).ftype = FTYPE_REGULAR;
                    (*inode).mode = S_IFREG_L | 0o644;
                    (*inode).parent_ino = (*parent).ino;
                    (*inode).rw_data = core::ptr::null_mut();
                    dir_add_entry(parent, child_name, child_len, (*inode).ino);
                }
            }

            if inode.is_null() {
                (*reply).label = SALTY_NOT_FOUND;
                return;
            }
        } else if (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL) {
            (*reply).label = SALTY_ALREADY_EXISTS;
            return;
        }

        // Validate access mode
        if (*inode).ftype == FTYPE_DIRECTORY {
            if flags_allow_write(flags) || (flags & (O_TRUNC | O_APPEND)) != 0 {
                (*reply).label = SALTY_INVALID_OPERATION;
                return;
            }
        }

        if (*inode).ftype == FTYPE_REGULAR {
            if (*inode).readonly != 0
                && (flags_allow_write(flags) || (flags & (O_TRUNC | O_APPEND)) != 0)
            {
                (*reply).label = SALTY_INVALID_OPERATION;
                return;
            }
            if (flags & O_TRUNC) != 0 && flags_allow_write(flags) {
                if !(*inode).rw_data.is_null() {
                    chain_truncate((*inode).rw_data, 0);
                }
                (*inode).size = 0;
            }
        }

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        for fd in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(fd)).active == 0 {
                (*(*cli).fds.add(fd)).active = 1;
                (*(*cli).fds.add(fd)).inode = (*inode).ino;
                (*(*cli).fds.add(fd)).offset = 0;
                (*(*cli).fds.add(fd)).dir_cursor = 0;
                (*(*cli).fds.add(fd)).flags = flags;

                if (*inode).ftype == FTYPE_CHAR_DEVICE {
                    (*(*cli).fds.add(fd)).fd_type = FD_TYPE_DEVICE;
                    (*(*cli).fds.add(fd)).dev_type = (*inode).dev_type;
                    if (*inode).dev_type == DEV_PTY_SLAVE {
                        (*(*cli).fds.add(fd)).sock_id = (*inode).size as u32; // pty_id
                    }
                } else if (*inode).ftype == FTYPE_DIRECTORY {
                    (*(*cli).fds.add(fd)).fd_type = FD_TYPE_DIR;
                } else if (*inode).ftype == FTYPE_FIFO {
                    // FIFO: create pipe fd using the pipe_id stored in inode.size
                    let pipe_id = (*inode).size as u32;
                    let pipe = find_pipe(pipe_id);
                    if pipe.is_null() {
                        (*(*cli).fds.add(fd)).active = 0;
                        (*reply).label = SALTY_INVALID_OPERATION;
                        return;
                    }
                    (*(*cli).fds.add(fd)).fd_type = FD_TYPE_PIPE;
                    (*(*cli).fds.add(fd)).sock_id = pipe_id;
                    if flags_allow_write(flags) {
                        (*(*cli).fds.add(fd)).flags = O_WRONLY;
                        (*pipe).write_refcount += 1;
                    } else {
                        (*(*cli).fds.add(fd)).flags = 0; // O_RDONLY
                        (*pipe).read_refcount += 1;
                    }
                } else {
                    (*(*cli).fds.add(fd)).fd_type = FD_TYPE_FILE;
                    if (flags & O_APPEND) != 0 {
                        (*(*cli).fds.add(fd)).offset = (*inode).size;
                    }
                }

                inode_open((*inode).ino);
                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = fd as u64;
                return;
            }
        }

        (*reply).label = SALTY_OUT_OF_MEMORY;
    }
}

unsafe fn handle_read(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let mut count = (*msg).regs[1];

        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32 || (*(*cli).fds.add(fd as usize)).active == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        if count > 152 {
            count = 152;
        }

        if !flags_allow_read((*(*cli).fds.add(fd as usize)).flags) {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let fde = &mut *(*cli).fds.add(fd as usize);

        match fde.fd_type {
            FD_TYPE_DEVICE => match fde.dev_type {
                DEV_CONSOLE => {
                    let mut creq = SaltyMsg::zeroed();
                    let mut creply = SaltyMsg::zeroed();
                    creq.label = CONSOLE_READ;
                    creq.length = 0;

                    let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_CONSOLE_EP, &raw const creq, &raw mut creply);
                    if err != 0 || creply.label != SALTY_OK {
                        (*reply).label = SALTY_INVALID_OPERATION;
                        return;
                    }

                    let read_count = creply.regs[0];
                    if read_count == 0 {
                        (*reply).label = SALTY_OK;
                        (*reply).length = 1;
                        (*reply).regs[0] = 0;
                    } else {
                        let actual = if read_count > count { count } else { read_count };
                        (*reply).label = SALTY_OK;
                        (*reply).length = 1 + (actual + 7) / 8;
                        (*reply).regs[0] = actual;
                        let src = &creply.regs[1] as *const u64 as *const u8;
                        let dst = &raw mut (*reply).regs[1] as *mut u8;
                        for i in 0..actual as usize {
                            *dst.add(i) = *src.add(i);
                        }
                    }
                }
                DEV_NULL => {
                    (*reply).label = SALTY_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = 0;
                }
                DEV_ZERO => {
                    (*reply).label = SALTY_OK;
                    (*reply).length = 1 + (count + 7) / 8;
                    (*reply).regs[0] = count;
                    let data = &raw mut (*reply).regs[1] as *mut u8;
                    for i in 0..count as usize {
                        *data.add(i) = 0;
                    }
                }
                DEV_URANDOM => {
                    (*reply).label = SALTY_OK;
                    (*reply).length = 1 + (count + 7) / 8;
                    (*reply).regs[0] = count;
                    let data = &raw mut (*reply).regs[1] as *mut u8;
                    let mut i: u64 = 0;
                    while i + 8 <= count {
                        let v = urandom_next();
                        let bytes = v.to_le_bytes();
                        for j in 0..8 {
                            *data.add(i as usize + j) = bytes[j];
                        }
                        i += 8;
                    }
                    if i < count {
                        let v = urandom_next();
                        let bytes = v.to_le_bytes();
                        let mut j = 0usize;
                        while i < count {
                            *data.add(i as usize) = bytes[j];
                            i += 1;
                            j += 1;
                        }
                    }
                }
                DEV_FB0 => {
                    (*reply).label = SALTY_INVALID_OPERATION;
                }
                DEV_PTY_SLAVE => {
                    // PTY reads should go through main loop dispatch for deferred support.
                    // If we end up here, do a non-blocking try-read.
                    let pty_id = fde.sock_id as u64;
                    let mut treq = SaltyMsg::zeroed();
                    let mut treply = SaltyMsg::zeroed();
                    treq.label = TTYD_PTY_READ;
                    treq.regs[0] = pty_id;
                    treq.regs[1] = count;
                    treq.length = 2;
                    let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
                    if err != 0 || treply.label != SALTY_OK {
                        (*reply).label = SALTY_INVALID_OPERATION;
                        return;
                    }
                    let actual = treply.regs[0];
                    (*reply).label = SALTY_OK;
                    (*reply).length = 1 + (actual + 7) / 8;
                    (*reply).regs[0] = actual;
                    if actual > 0 {
                        let src = &treply.regs[1] as *const u64 as *const u8;
                        let dst = &raw mut (*reply).regs[1] as *mut u8;
                        for i in 0..actual as usize {
                            *dst.add(i) = *src.add(i);
                        }
                    }
                }
                _ => {
                    (*reply).label = SALTY_INVALID_OPERATION;
                }
            },
            FD_TYPE_FILE => {
                let inode = inode_by_ino(fde.inode);
                if inode.is_null() {
                    (*reply).label = SALTY_INVALID_ARGUMENT;
                    return;
                }

                // /proc virtual files
                if (*inode).ftype == FTYPE_PROC_FILE {
                    let offset = fde.offset;
                    handle_proc_read(inode, offset, reply);
                    let bytes_read = (*reply).regs[0];
                    (*(*cli).fds.add(fd as usize)).offset += bytes_read;
                    return;
                }

                let offset = fde.offset;
                if offset >= (*inode).size {
                    (*reply).label = SALTY_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = 0;
                    return;
                }

                let avail = (*inode).size - offset;
                if count > avail {
                    count = avail;
                }

                let dst = &raw mut (*reply).regs[1] as *mut u8;
                if !(*inode).ro_data.is_null() {
                    let src = (*inode).ro_data.add(offset as usize);
                    for i in 0..count as usize {
                        *dst.add(i) = *src.add(i);
                    }
                } else if !(*inode).rw_data.is_null() {
                    let actual = chain_read((*inode).rw_data, offset, dst, count);
                    count = actual;
                } else {
                    (*reply).label = SALTY_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = 0;
                    return;
                }

                (*reply).label = SALTY_OK;
                (*reply).length = 1 + (count + 7) / 8;
                (*reply).regs[0] = count;

                fde.offset = offset + count;
            }
            _ => {
                (*reply).label = SALTY_INVALID_OPERATION;
            }
        }
    }
}

unsafe fn handle_write(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let mut count = (*msg).regs[1];

        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32 || (*(*cli).fds.add(fd as usize)).active == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        if count > 144 {
            count = 144;
        }

        if !flags_allow_write((*(*cli).fds.add(fd as usize)).flags) {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let fde = &mut *(*cli).fds.add(fd as usize);

        match fde.fd_type {
            FD_TYPE_DEVICE => match fde.dev_type {
                DEV_CONSOLE => {
                    let src = &(*msg).regs[2] as *const u64 as *const u8;
                    let mut sent: u64 = 0;
                    while sent < count {
                        let mut creq = SaltyMsg::zeroed();
                        let mut creply = SaltyMsg::zeroed();
                        let mut chunk = count - sent;
                        if chunk > 24 {
                            chunk = 24;
                        }

                        creq.label = CONSOLE_WRITE;
                        creq.length = 1 + (chunk + 7) / 8;
                        creq.regs[0] = chunk;

                        let dst = &raw mut creq.regs[1] as *mut u8;
                        for i in 0..chunk as usize {
                            *dst.add(i) = *src.add(sent as usize + i);
                        }

                        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_CONSOLE_EP, &raw const creq, &raw mut creply);
                        if err != 0 || creply.label != SALTY_OK {
                            break;
                        }
                        sent += chunk;
                    }
                    (*reply).label = if sent > 0 { SALTY_OK } else { SALTY_INVALID_OPERATION };
                    (*reply).length = 1;
                    (*reply).regs[0] = sent;
                }
                DEV_NULL | DEV_ZERO | DEV_URANDOM => {
                    (*reply).label = SALTY_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = count;
                }
                DEV_PTY_SLAVE => {
                    // Forward write to ttyd for OPOST processing + serial/display output
                    let pty_id = fde.sock_id as u64;
                    let src = &(*msg).regs[2] as *const u64 as *const u8;
                    let mut sent: u64 = 0;
                    while sent < count {
                        let mut treq = SaltyMsg::zeroed();
                        let mut treply = SaltyMsg::zeroed();
                        let mut chunk = count - sent;
                        if chunk > 136 { // 17 regs * 8 bytes (regs[2..19])
                            chunk = 136;
                        }
                        treq.label = TTYD_PTY_WRITE;
                        treq.regs[0] = pty_id;
                        treq.regs[1] = chunk;
                        let dst = &raw mut treq.regs[2] as *mut u8;
                        for i in 0..chunk as usize {
                            *dst.add(i) = *src.add(sent as usize + i);
                        }
                        treq.length = 2 + (chunk + 7) / 8;
                        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
                        if err != 0 || treply.label != SALTY_OK {
                            break;
                        }
                        sent += chunk;
                    }
                    (*reply).label = if sent > 0 { SALTY_OK } else { SALTY_INVALID_OPERATION };
                    (*reply).length = 1;
                    (*reply).regs[0] = sent;
                }
                DEV_FB0 => {
                    (*reply).label = SALTY_INVALID_OPERATION;
                }
                _ => {
                    (*reply).label = SALTY_INVALID_OPERATION;
                }
            },
            FD_TYPE_FILE => {
                let inode = inode_by_ino(fde.inode);
                if inode.is_null() || (*inode).readonly != 0 {
                    (*reply).label = SALTY_INVALID_OPERATION;
                    return;
                }

                if (*inode).rw_data.is_null() {
                    (*inode).rw_data = alloc_writable();
                    if (*inode).rw_data.is_null() {
                        (*reply).label = SALTY_OUT_OF_MEMORY;
                        return;
                    }
                }

                let mut offset = fde.offset;
                if (fde.flags & O_APPEND) != 0 {
                    offset = (*inode).size;
                }

                let src = &(*msg).regs[2] as *const u64 as *const u8;
                let written = chain_write((*inode).rw_data, offset, src, count);
                if written == 0 && count > 0 {
                    (*reply).label = SALTY_OUT_OF_MEMORY;
                    return;
                }
                count = written;

                fde.offset = offset + count;
                if fde.offset > (*inode).size {
                    (*inode).size = fde.offset;
                }

                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = count;
            }
            _ => {
                (*reply).label = SALTY_INVALID_OPERATION;
            }
        }
    }
}

unsafe fn handle_close(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32 || (*(*cli).fds.add(fd as usize)).active == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let fde = *(*cli).fds.add(fd as usize);

        // SHM close: tell mmsrv to unmap the SHM pages from this client
        if fde.fd_type == FD_TYPE_SHM && fde.offset != 0 {
            let inode = inode_by_ino(fde.inode);
            if !inode.is_null() && (*inode).ftype == FTYPE_SHM {
                let shm_idx = (*inode).dev_type as usize;
                let mut mm_msg = SaltyMsg::zeroed();
                let mut mm_reply_msg = SaltyMsg::zeroed();
                mm_msg.label = MM_SHM_UNMAP;
                mm_msg.length = 3;
                mm_msg.regs[0] = shm_idx as u64;
                mm_msg.regs[1] = badge;
                mm_msg.regs[2] = fde.offset; // mapped vaddr
                let _ = ipc::call_ctx(
                    ipc_ctx(),
                    VFS_CAP_MMSRV_EP,
                    &raw const mm_msg,
                    &raw mut mm_reply_msg,
                );
            }
        }

        // Decrement inode open count
        if fde.fd_type != FD_TYPE_PIPE && fde.fd_type != FD_TYPE_SOCKET {
            inode_close(fde.inode);
        }

        (*(*cli).fds.add(fd as usize)).active = 0;
        (*reply).label = SALTY_OK;
    }
}

unsafe fn handle_lseek(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let offset = (*msg).regs[1] as i64;
        let whence = (*msg).regs[2] as i32;

        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32 || (*(*cli).fds.add(fd as usize)).active == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let fdt = (*(*cli).fds.add(fd as usize)).fd_type;
        if fdt != FD_TYPE_FILE && fdt != FD_TYPE_MOUNT {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        // For mount FDs, we need the file size from the remote FS for SEEK_END
        let file_size: u64 = if fdt == FD_TYPE_MOUNT {
            let fde = &*(*cli).fds.add(fd as usize);
            match mount_stat(fde.dev_type as usize, fde.sock_id as u64) {
                Some((size, _, _, _, _)) => size,
                None => 0,
            }
        } else {
            let inode = inode_by_ino((*(*cli).fds.add(fd as usize)).inode);
            if inode.is_null() {
                (*reply).label = SALTY_INVALID_ARGUMENT;
                return;
            }
            (*inode).size
        };

        let new_offset: i64 = match whence {
            0 => offset, // SEEK_SET
            1 => (*(*cli).fds.add(fd as usize)).offset as i64 + offset, // SEEK_CUR
            2 => file_size as i64 + offset, // SEEK_END
            _ => {
                (*reply).label = SALTY_INVALID_ARGUMENT;
                return;
            }
        };

        if new_offset < 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        (*(*cli).fds.add(fd as usize)).offset = new_offset as u64;
        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = new_offset as u64;
    }
}

unsafe fn fill_stat_reply(reply: *mut SaltyMsg, inode: *const RamfsInode) {
    unsafe {
        (*reply).label = SALTY_OK;
        (*reply).length = 8;
        (*reply).regs[0] = (*inode).ino as u64;
        (*reply).regs[1] = (*inode).mode as u64;
        (*reply).regs[2] = (*inode).nlink as u64;
        (*reply).regs[3] = (*inode).size;
        (*reply).regs[4] = 0; // uid
        (*reply).regs[5] = 0; // gid
        (*reply).regs[6] = (*inode).mtime as u64;
        (*reply).regs[7] = if (*inode).ftype == FTYPE_MOUNT_POINT {
            FTYPE_DIRECTORY as u64
        } else {
            (*inode).ftype as u64
        };
    }
}

unsafe fn handle_fstat(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32 || (*(*cli).fds.add(fd as usize)).active == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Mount FD: proxy stat to remote FS
        if (*(*cli).fds.add(fd as usize)).fd_type == FD_TYPE_MOUNT {
            let fde = &*(*cli).fds.add(fd as usize);
            let mount_idx = fde.dev_type as usize;
            let remote_ino = fde.sock_id as u64;
            match mount_stat(mount_idx, remote_ino) {
                Some((size, mode, nlink, mtime, _)) => {
                    (*reply).label = SALTY_OK;
                    (*reply).length = 8;
                    (*reply).regs[0] = remote_ino;
                    (*reply).regs[1] = mode as u64;
                    (*reply).regs[2] = nlink as u64;
                    (*reply).regs[3] = size;
                    (*reply).regs[4] = 0;
                    (*reply).regs[5] = 0;
                    (*reply).regs[6] = mtime;
                    (*reply).regs[7] = if (mode & S_IFMT_L) == S_IFDIR_L {
                        FTYPE_DIRECTORY as u64
                    } else {
                        FTYPE_REGULAR as u64
                    };
                }
                None => {
                    (*reply).label = SALTY_INVALID_ARGUMENT;
                }
            }
            return;
        }

        let inode = inode_by_ino((*(*cli).fds.add(fd as usize)).inode);
        if inode.is_null() {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        fill_stat_reply(reply, inode);
    }
}

unsafe fn get_client_cwd_ino(badge: u64) -> u32 {
    unsafe {
        let cli = get_client_noalloc(badge);
        if cli.is_null() {
            return ROOT_INO;
        }
        let mut cwd_len: usize = 0;
        while cwd_len < 128 && (*cli).cwd[cwd_len] != 0 {
            cwd_len += 1;
        }
        if cwd_len == 0 {
            return ROOT_INO;
        }
        let inode = resolve_path((*cli).cwd.as_ptr(), cwd_len as u8);
        if inode.is_null() { ROOT_INO } else { (*inode).ino }
    }
}

/// Normalize a user path to canonical absolute form using the caller's cwd.
/// This collapses repeated '/', '.' and '..' components.
/// Returns (absolute_path_ptr, absolute_len).
unsafe fn normalize_path_for_client(
    badge: u64,
    in_path: *const u8,
    in_len: u8,
    tmp_abs: *mut u8,
) -> Option<(*const u8, u8)> {
    unsafe {
        if in_len == 0 {
            return None;
        }
        let mut raw_abs = [0u8; MAX_PATH_LEN];
        let raw_len: usize;

        if *in_path == b'/' {
            raw_len = in_len as usize;
            if raw_len == 0 || raw_len > MAX_PATH_LEN {
                return None;
            }
            for i in 0..raw_len {
                raw_abs[i] = *in_path.add(i);
            }
        } else {
            let cli = get_client_noalloc(badge);
            if cli.is_null() {
                return None;
            }

            let mut cwd_len: usize = 0;
            while cwd_len < 128 && (*cli).cwd[cwd_len] != 0 {
                cwd_len += 1;
            }
            if cwd_len == 0 {
                cwd_len = 1;
            }

            let cwd_is_root = cwd_len == 1 && (*cli).cwd[0] == b'/';
            let rel_len = in_len as usize;
            raw_len = if cwd_is_root { 1 + rel_len } else { cwd_len + 1 + rel_len };
            if raw_len > MAX_PATH_LEN {
                return None;
            }

            if cwd_is_root {
                raw_abs[0] = b'/';
                for i in 0..rel_len {
                    raw_abs[1 + i] = *in_path.add(i);
                }
            } else {
                for i in 0..cwd_len {
                    raw_abs[i] = (*cli).cwd[i];
                }
                raw_abs[cwd_len] = b'/';
                for i in 0..rel_len {
                    raw_abs[cwd_len + 1 + i] = *in_path.add(i);
                }
            }
        }

        // Canonicalize absolute path in raw_abs into tmp_abs.
        // Output always starts with '/' and has no trailing slash except root.
        let mut out_len: usize = 1;
        *tmp_abs = b'/';
        let mut comp_starts = [0usize; MAX_PATH_LEN / 2];
        let mut depth: usize = 0;

        let mut pos: usize = 0;
        if raw_len > 0 && raw_abs[0] == b'/' {
            pos = 1;
        }

        while pos < raw_len {
            while pos < raw_len && raw_abs[pos] == b'/' {
                pos += 1;
            }
            if pos >= raw_len {
                break;
            }

            let start = pos;
            while pos < raw_len && raw_abs[pos] != b'/' {
                pos += 1;
            }
            let seg_len = pos - start;
            if seg_len == 0 {
                continue;
            }

            if seg_len == 1 && raw_abs[start] == b'.' {
                continue;
            }
            if seg_len == 2 && raw_abs[start] == b'.' && raw_abs[start + 1] == b'.' {
                if depth > 0 {
                    depth -= 1;
                    out_len = comp_starts[depth];
                    if out_len == 0 {
                        out_len = 1;
                        *tmp_abs = b'/';
                    }
                }
                continue;
            }

            if depth >= comp_starts.len() {
                return None;
            }
            if out_len > 1 {
                if out_len >= MAX_PATH_LEN {
                    return None;
                }
                *tmp_abs.add(out_len) = b'/';
                out_len += 1;
            }
            comp_starts[depth] = out_len;
            depth += 1;

            if out_len + seg_len > MAX_PATH_LEN {
                return None;
            }
            for i in 0..seg_len {
                *tmp_abs.add(out_len + i) = raw_abs[start + i];
            }
            out_len += seg_len;
        }

        if out_len == 0 || out_len > u8::MAX as usize {
            return None;
        }
        Some((tmp_abs as *const u8, out_len as u8))
    }
}

unsafe fn handle_stat(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) = normalize_path_for_client(
            badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };
        let path_slice = core::slice::from_raw_parts(path_ptr, path_len as usize);

        // Mount point intercept for stat
        if let Some(mount_idx) = find_mount_for_path(path_slice, path_len) {
            let (_, sub_start, sub_len) = parse_mount_path(path_slice, path_len);
            if sub_len > 0 {
                let remote_ino = mount_lookup(mount_idx, path_ptr.add(sub_start), sub_len);
                if remote_ino == 0 {
                    (*reply).label = SALTY_NOT_FOUND;
                    return;
                }
                match mount_stat(mount_idx, remote_ino) {
                    Some((size, mode, nlink, mtime, _)) => {
                        (*reply).label = SALTY_OK;
                        (*reply).length = 8;
                        (*reply).regs[0] = remote_ino;
                        (*reply).regs[1] = mode as u64;
                        (*reply).regs[2] = nlink as u64;
                        (*reply).regs[3] = size;
                        (*reply).regs[4] = 0; // uid
                        (*reply).regs[5] = 0; // gid
                        (*reply).regs[6] = mtime;
                        (*reply).regs[7] = if (mode & S_IFMT_L) == S_IFDIR_L {
                            FTYPE_DIRECTORY as u64
                        } else {
                            FTYPE_REGULAR as u64
                        };
                    }
                    None => {
                        (*reply).label = SALTY_NOT_FOUND;
                    }
                }
                return;
            }
            // Exact mount point — fall through to local resolve
        }

        let inode = resolve_path(path_ptr, path_len);
        if inode.is_null() {
            // Try /proc virtual paths
            if path_len >= 6 && *path_ptr == b'/' && *path_ptr.add(1) == b'p'
                && *path_ptr.add(2) == b'r' && *path_ptr.add(3) == b'o'
                && *path_ptr.add(4) == b'c' && *path_ptr.add(5) == b'/'
            {
                if handle_proc_stat(path_ptr, path_len, reply, badge) {
                    return;
                }
            }
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }
        fill_stat_reply(reply, inode);
    }
}

unsafe fn handle_access(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 1, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) = normalize_path_for_client(
            badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };
        let inode = resolve_path(path_ptr, path_len);
        if inode.is_null() {
            // /proc virtual paths always accessible (read-only)
            if path_len >= 6 && *path_ptr == b'/' && *path_ptr.add(1) == b'p'
                && *path_ptr.add(2) == b'r' && *path_ptr.add(3) == b'o'
                && *path_ptr.add(4) == b'c' && *path_ptr.add(5) == b'/'
            {
                if handle_proc_stat(path_ptr, path_len, &mut SaltyMsg::zeroed(), badge) {
                    (*reply).label = SALTY_OK;
                    return;
                }
            }
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }
        (*reply).label = SALTY_OK;
    }
}

unsafe fn handle_unlink(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) = normalize_path_for_client(
            badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };

        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent(path_ptr, path_len, &mut child_name, &mut child_len);
        if parent.is_null() || (*parent).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let de = dir_find_entry(parent, child_name, child_len);
        if de.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let inode = inode_by_ino((*de).ino);
        if inode.is_null() || (*inode).ftype == FTYPE_DIRECTORY {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        (*de).active = 0;
        (*inode).nlink = (*inode).nlink.saturating_sub(1);
        if (*inode).nlink == 0 && (*inode).open_count == 0 {
            free_inode(inode);
        }
        (*reply).label = SALTY_OK;
    }
}

unsafe fn handle_rename(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut old_len = (*msg).regs[0] as u8;
        let mut new_len = (*msg).regs[1] as u8;
        if (old_len as usize) > MAX_PATH_LEN {
            old_len = MAX_PATH_LEN as u8;
        }
        if (new_len as usize) > MAX_PATH_LEN {
            new_len = MAX_PATH_LEN as u8;
        }

        let mut old_path = [0u8; MAX_PATH_LEN];
        let mut new_path = [0u8; MAX_PATH_LEN];
        let mut old_abs = [0u8; MAX_PATH_LEN];
        let mut new_abs = [0u8; MAX_PATH_LEN];
        let raw = &(*msg).regs[2] as *const u64 as *const u8;
        for i in 0..old_len as usize {
            old_path[i] = *raw.add(i);
        }
        let raw2 = raw.add(((old_len as usize) + 7) / 8 * 8);
        for i in 0..new_len as usize {
            new_path[i] = *raw2.add(i);
        }
        if old_len == 0 || new_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let Some((old_ptr, old_norm_len)) = normalize_path_for_client(
            badge, old_path.as_ptr(), old_len, old_abs.as_mut_ptr(),
        ) else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };
        let Some((new_ptr, new_norm_len)) = normalize_path_for_client(
            badge, new_path.as_ptr(), new_len, new_abs.as_mut_ptr(),
        ) else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };

        // Resolve old parent + child
        let mut old_child: *const u8 = core::ptr::null();
        let mut old_child_len: u8 = 0;
        let old_parent =
            resolve_parent(old_ptr, old_norm_len, &mut old_child, &mut old_child_len);
        if old_parent.is_null() || (*old_parent).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let de = dir_find_entry(old_parent, old_child, old_child_len);
        if de.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }
        let ino = (*de).ino;

        // Resolve new parent + child
        let mut new_child: *const u8 = core::ptr::null();
        let mut new_child_len: u8 = 0;
        let new_parent =
            resolve_parent(new_ptr, new_norm_len, &mut new_child, &mut new_child_len);
        if new_parent.is_null() || (*new_parent).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        // Remove from old
        (*de).active = 0;

        // Remove existing at new location
        let existing = dir_find_entry(new_parent, new_child, new_child_len);
        if !existing.is_null() {
            let old_inode = inode_by_ino((*existing).ino);
            if !old_inode.is_null() {
                (*old_inode).nlink = (*old_inode).nlink.saturating_sub(1);
                if (*old_inode).nlink == 0 && (*old_inode).open_count == 0 {
                    free_inode(old_inode);
                }
            }
            (*existing).active = 0;
        }

        dir_add_entry(new_parent, new_child, new_child_len, ino);
        (*reply).label = SALTY_OK;
    }
}

unsafe fn handle_mkdir(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 1, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) = normalize_path_for_client(
            badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };

        let existing = resolve_path(path_ptr, path_len);
        if !existing.is_null() {
            (*reply).label = SALTY_ALREADY_EXISTS;
            return;
        }

        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent(path_ptr, path_len, &mut child_name, &mut child_len);
        if parent.is_null() || (*parent).ftype != FTYPE_DIRECTORY || (*parent).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let dir = alloc_inode();
        if dir.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        (*dir).ftype = FTYPE_DIRECTORY;
        (*dir).mode = S_IFDIR_L | ((*msg).regs[0] as u32 & 0o777);
        (*dir).nlink = 2;
        (*dir).parent_ino = (*parent).ino;

        dir_add_entry(parent, child_name, child_len, (*dir).ino);
        (*reply).label = SALTY_OK;
    }
}

unsafe fn handle_mkfifo(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 1, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) = normalize_path_for_client(
            badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };

        let existing = resolve_path(path_ptr, path_len);
        if !existing.is_null() {
            (*reply).label = SALTY_ALREADY_EXISTS;
            return;
        }

        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent(path_ptr, path_len, &mut child_name, &mut child_len);
        if parent.is_null() || (*parent).ftype != FTYPE_DIRECTORY || (*parent).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        // Allocate a pipe for the FIFO
        let pipe = alloc_pipe();
        if pipe.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        let fifo = alloc_inode();
        if fifo.is_null() {
            (*pipe).active = 0;
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        (*fifo).ftype = FTYPE_FIFO;
        (*fifo).mode = S_IFREG_L | 0o666; // Use regular file mode bits for FIFO
        (*fifo).nlink = 1;
        (*fifo).parent_ino = (*parent).ino;
        (*fifo).size = (*pipe).pipe_id as u64; // Store pipe_id in size field

        dir_add_entry(parent, child_name, child_len, (*fifo).ino);
        (*reply).label = SALTY_OK;
    }
}

unsafe fn handle_rmdir(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) = normalize_path_for_client(
            badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };

        let inode = resolve_path(path_ptr, path_len);
        if inode.is_null() || (*inode).ftype != FTYPE_DIRECTORY {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        if (*inode).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        // Check directory is empty
        for i in 0..(*inode).dirents_cap as usize {
            if (*(*inode).dirents.add(i)).active != 0 {
                (*reply).label = SALTY_INVALID_OPERATION;
                return;
            }
        }

        // Remove from parent
        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent(path_ptr, path_len, &mut child_name, &mut child_len);
        if !parent.is_null() {
            dir_remove_entry(parent, child_name, child_len);
        }

        (*inode).active = 0;
        (*reply).label = SALTY_OK;
    }
}

// ======================================================================
// *at() family handlers
// ======================================================================

/// Inner open logic parameterized by start_ino.
/// Reused by handle_open (start_ino=ROOT_INO) and handle_openat.
unsafe fn do_open(
    start_ino: u32,
    path: *const u8,
    path_len: u8,
    flags: u32,
    reply: *mut SaltyMsg,
    badge: u64,
) {
    unsafe {
        if path_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // /proc virtual paths — intercept absolute paths before resolve
        if path_len >= 6 {
            let p = path;
            if *p == b'/' && *p.add(1) == b'p' && *p.add(2) == b'r'
                && *p.add(3) == b'o' && *p.add(4) == b'c' && *p.add(5) == b'/'
            {
                if handle_proc_open(path, path_len, reply, badge) {
                    return;
                }
            }
        }

        let mut inode = resolve_path_from(start_ino, path, path_len);

        if inode.is_null() {
            if (flags & O_CREAT) == 0 {
                (*reply).label = SALTY_NOT_FOUND;
                return;
            }

            let mut child_name: *const u8 = core::ptr::null();
            let mut child_len: u8 = 0;
            let parent = resolve_parent_from(start_ino, path, path_len, &mut child_name, &mut child_len);
            if !parent.is_null()
                && (*parent).ftype == FTYPE_DIRECTORY
                && (*parent).readonly == 0
                && child_len > 0
            {
                inode = alloc_inode();
                if !inode.is_null() {
                    (*inode).ftype = FTYPE_REGULAR;
                    (*inode).mode = S_IFREG_L | 0o644;
                    (*inode).parent_ino = (*parent).ino;
                    (*inode).rw_data = core::ptr::null_mut();
                    dir_add_entry(parent, child_name, child_len, (*inode).ino);
                }
            }

            if inode.is_null() {
                (*reply).label = SALTY_NOT_FOUND;
                return;
            }
        } else if (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL) {
            (*reply).label = SALTY_ALREADY_EXISTS;
            return;
        }

        if (*inode).ftype == FTYPE_DIRECTORY {
            if flags_allow_write(flags) || (flags & (O_TRUNC | O_APPEND)) != 0 {
                (*reply).label = SALTY_INVALID_OPERATION;
                return;
            }
        }

        if (*inode).ftype == FTYPE_REGULAR {
            if (*inode).readonly != 0
                && (flags_allow_write(flags) || (flags & (O_TRUNC | O_APPEND)) != 0)
            {
                (*reply).label = SALTY_INVALID_OPERATION;
                return;
            }
            if (flags & O_TRUNC) != 0 && flags_allow_write(flags) {
                if !(*inode).rw_data.is_null() {
                    chain_truncate((*inode).rw_data, 0);
                }
                (*inode).size = 0;
            }
        }

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        for fd in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(fd)).active == 0 {
                (*(*cli).fds.add(fd)).active = 1;
                (*(*cli).fds.add(fd)).inode = (*inode).ino;
                (*(*cli).fds.add(fd)).offset = 0;
                (*(*cli).fds.add(fd)).dir_cursor = 0;
                (*(*cli).fds.add(fd)).flags = flags;

                if (*inode).ftype == FTYPE_CHAR_DEVICE {
                    (*(*cli).fds.add(fd)).fd_type = FD_TYPE_DEVICE;
                    (*(*cli).fds.add(fd)).dev_type = (*inode).dev_type;
                    if (*inode).dev_type == DEV_PTY_SLAVE {
                        (*(*cli).fds.add(fd)).sock_id = (*inode).size as u32; // pty_id
                    }
                } else if (*inode).ftype == FTYPE_DIRECTORY {
                    (*(*cli).fds.add(fd)).fd_type = FD_TYPE_DIR;
                } else if (*inode).ftype == FTYPE_FIFO {
                    let pipe_id = (*inode).size as u32;
                    let pipe = find_pipe(pipe_id);
                    if pipe.is_null() {
                        (*(*cli).fds.add(fd)).active = 0;
                        (*reply).label = SALTY_INVALID_OPERATION;
                        return;
                    }
                    (*(*cli).fds.add(fd)).fd_type = FD_TYPE_PIPE;
                    (*(*cli).fds.add(fd)).sock_id = pipe_id;
                    if flags_allow_write(flags) {
                        (*(*cli).fds.add(fd)).flags = O_WRONLY;
                        (*pipe).write_refcount += 1;
                    } else {
                        (*(*cli).fds.add(fd)).flags = 0;
                        (*pipe).read_refcount += 1;
                    }
                } else {
                    (*(*cli).fds.add(fd)).fd_type = FD_TYPE_FILE;
                    if (flags & O_APPEND) != 0 {
                        (*(*cli).fds.add(fd)).offset = (*inode).size;
                    }
                }

                inode_open((*inode).ino);
                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = fd as u64;
                return;
            }
        }

        (*reply).label = SALTY_OUT_OF_MEMORY;
    }
}

/// openat(dirfd, path, flags)
/// IPC: reg[0]=dirfd, reg[1]=open_flags, reg[2..]=path(len+data)
unsafe fn handle_openat(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let flags = (*msg).regs[1] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 2, path.as_mut_ptr());

        let start_ino = resolve_at_start(badge, dirfd, path.as_ptr(), path_len);
        if start_ino == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        do_open(start_ino, path.as_ptr(), path_len, flags, reply, badge);
    }
}

/// fstatat(dirfd, path, statbuf, flags)
/// IPC: reg[0]=dirfd, reg[1]=at_flags, reg[2..]=path(len+data)
unsafe fn handle_fstatat(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let at_flags = (*msg).regs[1] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 2, path.as_mut_ptr());

        let start_ino = resolve_at_start(badge, dirfd, path.as_ptr(), path_len);
        if start_ino == 0 && !((at_flags & AT_EMPTY_PATH_VAL) != 0 && path_len == 0) {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let inode = if path_len == 0 && (at_flags & AT_EMPTY_PATH_VAL) != 0 {
            // AT_EMPTY_PATH: stat the fd itself
            if dirfd < 0 {
                (*reply).label = SALTY_INVALID_ARGUMENT;
                return;
            }
            let cli = get_client(badge);
            if cli.is_null() || dirfd >= (*cli).fds_cap as i32
                || (*(*cli).fds.add(dirfd as usize)).active == 0
            {
                (*reply).label = SALTY_INVALID_ARGUMENT;
                return;
            }
            inode_by_ino((*(*cli).fds.add(dirfd as usize)).inode)
        } else {
            resolve_path_from(start_ino, path.as_ptr(), path_len)
        };

        if inode.is_null() {
            // Try /proc virtual paths
            if path_len >= 6 && path[0] == b'/' && path[1] == b'p' && path[2] == b'r'
                && path[3] == b'o' && path[4] == b'c' && path[5] == b'/'
            {
                if handle_proc_stat(path.as_ptr(), path_len, reply, badge) {
                    return;
                }
            }
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }
        fill_stat_reply(reply, inode);
    }
}

/// unlinkat(dirfd, path, flags)
/// IPC: reg[0]=dirfd, reg[1]=at_flags, reg[2..]=path(len+data)
unsafe fn handle_unlinkat(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let at_flags = (*msg).regs[1] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 2, path.as_mut_ptr());

        let start_ino = resolve_at_start(badge, dirfd, path.as_ptr(), path_len);
        if start_ino == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        if (at_flags & AT_REMOVEDIR_VAL) != 0 {
            // AT_REMOVEDIR: act like rmdir
            let inode = resolve_path_from(start_ino, path.as_ptr(), path_len);
            if inode.is_null() || (*inode).ftype != FTYPE_DIRECTORY {
                (*reply).label = SALTY_NOT_FOUND;
                return;
            }
            if (*inode).readonly != 0 {
                (*reply).label = SALTY_INVALID_OPERATION;
                return;
            }
            for i in 0..(*inode).dirents_cap as usize {
                if (*(*inode).dirents.add(i)).active != 0 {
                    (*reply).label = SALTY_INVALID_OPERATION;
                    return;
                }
            }
            let mut child_name: *const u8 = core::ptr::null();
            let mut child_len: u8 = 0;
            let parent = resolve_parent_from(
                start_ino, path.as_ptr(), path_len, &mut child_name, &mut child_len,
            );
            if !parent.is_null() {
                dir_remove_entry(parent, child_name, child_len);
            }
            (*inode).active = 0;
            (*reply).label = SALTY_OK;
        } else {
            // Regular unlink
            let mut child_name: *const u8 = core::ptr::null();
            let mut child_len: u8 = 0;
            let parent = resolve_parent_from(
                start_ino, path.as_ptr(), path_len, &mut child_name, &mut child_len,
            );
            if parent.is_null() || (*parent).readonly != 0 {
                (*reply).label = SALTY_INVALID_OPERATION;
                return;
            }
            let de = dir_find_entry(parent, child_name, child_len);
            if de.is_null() {
                (*reply).label = SALTY_NOT_FOUND;
                return;
            }
            let inode = inode_by_ino((*de).ino);
            if inode.is_null() || (*inode).ftype == FTYPE_DIRECTORY {
                (*reply).label = SALTY_INVALID_OPERATION;
                return;
            }
            (*de).active = 0;
            (*inode).nlink = (*inode).nlink.saturating_sub(1);
            if (*inode).nlink == 0 && (*inode).open_count == 0 {
                free_inode(inode);
            }
            (*reply).label = SALTY_OK;
        }
    }
}

/// renameat(old_dirfd, old_path, new_dirfd, new_path)
/// IPC: reg[0]=old_dirfd, reg[1]=new_dirfd, reg[2]=old_len, reg[3]=new_len, reg[4..]=paths
unsafe fn handle_renameat(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let old_dirfd = (*msg).regs[0] as i32;
        let new_dirfd = (*msg).regs[1] as i32;
        let mut old_len = (*msg).regs[2] as u8;
        let mut new_len = (*msg).regs[3] as u8;
        if (old_len as usize) > MAX_PATH_LEN {
            old_len = MAX_PATH_LEN as u8;
        }
        if (new_len as usize) > MAX_PATH_LEN {
            new_len = MAX_PATH_LEN as u8;
        }

        let mut old_path = [0u8; MAX_PATH_LEN];
        let mut new_path = [0u8; MAX_PATH_LEN];
        let raw = &(*msg).regs[4] as *const u64 as *const u8;
        for i in 0..old_len as usize {
            old_path[i] = *raw.add(i);
        }
        let raw2 = raw.add(((old_len as usize) + 7) / 8 * 8);
        for i in 0..new_len as usize {
            new_path[i] = *raw2.add(i);
        }

        let old_start = resolve_at_start(badge, old_dirfd, old_path.as_ptr(), old_len);
        let new_start = resolve_at_start(badge, new_dirfd, new_path.as_ptr(), new_len);
        if old_start == 0 || new_start == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let mut old_child: *const u8 = core::ptr::null();
        let mut old_child_len: u8 = 0;
        let old_parent = resolve_parent_from(
            old_start, old_path.as_ptr(), old_len, &mut old_child, &mut old_child_len,
        );
        if old_parent.is_null() || (*old_parent).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let de = dir_find_entry(old_parent, old_child, old_child_len);
        if de.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }
        let ino = (*de).ino;

        let mut new_child: *const u8 = core::ptr::null();
        let mut new_child_len: u8 = 0;
        let new_parent = resolve_parent_from(
            new_start, new_path.as_ptr(), new_len, &mut new_child, &mut new_child_len,
        );
        if new_parent.is_null() || (*new_parent).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        (*de).active = 0;

        let existing = dir_find_entry(new_parent, new_child, new_child_len);
        if !existing.is_null() {
            let old_inode = inode_by_ino((*existing).ino);
            if !old_inode.is_null() {
                (*old_inode).nlink = (*old_inode).nlink.saturating_sub(1);
                if (*old_inode).nlink == 0 && (*old_inode).open_count == 0 {
                    free_inode(old_inode);
                }
            }
            (*existing).active = 0;
        }

        dir_add_entry(new_parent, new_child, new_child_len, ino);
        (*reply).label = SALTY_OK;
    }
}

/// mkdirat(dirfd, path, mode)
/// IPC: reg[0]=dirfd, reg[1]=mode, reg[2..]=path(len+data)
unsafe fn handle_mkdirat(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mode = (*msg).regs[1] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 2, path.as_mut_ptr());

        let start_ino = resolve_at_start(badge, dirfd, path.as_ptr(), path_len);
        if start_ino == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let existing = resolve_path_from(start_ino, path.as_ptr(), path_len);
        if !existing.is_null() {
            (*reply).label = SALTY_ALREADY_EXISTS;
            return;
        }

        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent_from(
            start_ino, path.as_ptr(), path_len, &mut child_name, &mut child_len,
        );
        if parent.is_null() || (*parent).ftype != FTYPE_DIRECTORY || (*parent).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let dir = alloc_inode();
        if dir.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        (*dir).ftype = FTYPE_DIRECTORY;
        (*dir).mode = S_IFDIR_L | (mode & 0o777);
        (*dir).nlink = 2;
        (*dir).parent_ino = (*parent).ino;

        dir_add_entry(parent, child_name, child_len, (*dir).ino);
        (*reply).label = SALTY_OK;
    }
}

/// faccessat(dirfd, path, mode, flags)
/// IPC: reg[0]=dirfd, reg[1]=mode, reg[2]=at_flags, reg[3..]=path(len+data)
unsafe fn handle_faccessat(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 3, path.as_mut_ptr());

        let start_ino = resolve_at_start(badge, dirfd, path.as_ptr(), path_len);
        if start_ino == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let inode = resolve_path_from(start_ino, path.as_ptr(), path_len);
        if inode.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }
        (*reply).label = SALTY_OK;
    }
}

/// fchmodat(dirfd, path, mode, flags)
/// IPC: reg[0]=dirfd, reg[1]=mode, reg[2]=at_flags, reg[3..]=path(len+data)
/// Single-user OS — resolve path, verify exists, return OK.
unsafe fn handle_fchmodat(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 3, path.as_mut_ptr());

        let start_ino = resolve_at_start(badge, dirfd, path.as_ptr(), path_len);
        if start_ino == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let inode = resolve_path_from(start_ino, path.as_ptr(), path_len);
        if inode.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }
        (*reply).label = SALTY_OK;
    }
}

/// fchownat(dirfd, path, uid, gid, flags)
/// IPC: reg[0]=dirfd, reg[1]=uid, reg[2]=gid, reg[3]=at_flags, reg[4..]=path(len+data)
/// Single-user OS — resolve path, verify exists, return OK.
unsafe fn handle_fchownat(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 4, path.as_mut_ptr());

        let start_ino = resolve_at_start(badge, dirfd, path.as_ptr(), path_len);
        if start_ino == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let inode = resolve_path_from(start_ino, path.as_ptr(), path_len);
        if inode.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }
        (*reply).label = SALTY_OK;
    }
}

/// fchmod(fd, mode) — change mode on open fd
/// IPC: reg[0]=fd, reg[1]=mode
/// Single-user OS — verify fd exists, return OK.
unsafe fn handle_fchmod(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        (*reply).label = SALTY_OK;
    }
}

/// fchown(fd, uid, gid) — change owner on open fd
/// IPC: reg[0]=fd, reg[1]=uid, reg[2]=gid
/// Single-user OS — verify fd exists, return OK.
unsafe fn handle_fchown(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        (*reply).label = SALTY_OK;
    }
}

/// utimensat(dirfd, path, times, flags)
/// IPC: reg[0]=dirfd, reg[1]=at_flags, reg[2]=atime_sec, reg[3]=atime_nsec,
///      reg[4]=mtime_sec, reg[5]=mtime_nsec, reg[6..]=path(len+data)
unsafe fn handle_utimensat(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let dirfd = (*msg).regs[0] as i32;
        let at_flags = (*msg).regs[1] as i32;
        let _atime_sec = (*msg).regs[2] as i64;
        let _atime_nsec = (*msg).regs[3] as i64;
        let mtime_sec = (*msg).regs[4] as i64;
        let mtime_nsec = (*msg).regs[5] as i64;
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 6, path.as_mut_ptr());

        let inode = if path_len == 0 && (at_flags & AT_EMPTY_PATH_VAL) != 0 {
            // Operate on dirfd itself
            if dirfd < 0 || dirfd == AT_FDCWD_VAL {
                (*reply).label = SALTY_INVALID_ARGUMENT;
                return;
            }
            let cli = get_client(badge);
            if cli.is_null() || dirfd >= (*cli).fds_cap as i32
                || (*(*cli).fds.add(dirfd as usize)).active == 0
            {
                (*reply).label = SALTY_INVALID_ARGUMENT;
                return;
            }
            inode_by_ino((*(*cli).fds.add(dirfd as usize)).inode)
        } else {
            let start_ino = resolve_at_start(badge, dirfd, path.as_ptr(), path_len);
            if start_ino == 0 {
                (*reply).label = SALTY_INVALID_ARGUMENT;
                return;
            }
            resolve_path_from(start_ino, path.as_ptr(), path_len)
        };

        if inode.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        // UTIME_OMIT = (1<<30)-2 — don't change
        // UTIME_NOW = (1<<30)-1 — set to current time
        // Otherwise use provided value
        const UTIME_NOW_VAL: i64 = (1 << 30) - 1;
        const UTIME_OMIT_VAL: i64 = (1 << 30) - 2;

        if mtime_nsec != UTIME_OMIT_VAL {
            if mtime_nsec == UTIME_NOW_VAL {
                // Get current monotonic time
                let res = salty::syscall::syscall(
                    salty::consts::SYS_CLOCK_GETTIME, 0, 0, 0, 0, 0, 0,
                );
                let now_sec = res.value / 1_000_000_000;
                (*inode).mtime = now_sec as u32;
            } else {
                (*inode).mtime = mtime_sec as u32;
            }
        }

        (*reply).label = SALTY_OK;
    }
}

unsafe fn handle_opendir(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) = normalize_path_for_client(
            badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };
        let path_slice = core::slice::from_raw_parts(path_ptr, path_len as usize);

        // /proc sub-paths that don't resolve as real inodes
        if path_len >= 6 && *path_ptr == b'/' && *path_ptr.add(1) == b'p'
            && *path_ptr.add(2) == b'r' && *path_ptr.add(3) == b'o'
            && *path_ptr.add(4) == b'c' && *path_ptr.add(5) == b'/'
        {
            if handle_proc_open(path_ptr, path_len, reply, badge) {
                return;
            }
        }

        // Mount point intercept for opendir
        if let Some(mount_idx) = find_mount_for_path(path_slice, path_len) {
            let (_, sub_start, sub_len) = parse_mount_path(path_slice, path_len);
            let remote_ino = if sub_len > 0 {
                mount_lookup(mount_idx, path_ptr.add(sub_start), sub_len)
            } else {
                (*(&raw const MOUNTS[mount_idx])).root_ino as u64
            };
            if remote_ino == 0 {
                (*reply).label = SALTY_NOT_FOUND;
                return;
            }

            let cli = get_client(badge);
            if cli.is_null() {
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }
            for fd in 0..(*cli).fds_cap as usize {
                if (*(*cli).fds.add(fd)).active == 0 {
                    (*(*cli).fds.add(fd)).active = 1;
                    (*(*cli).fds.add(fd)).fd_type = FD_TYPE_MOUNT;
                    (*(*cli).fds.add(fd)).inode = MOUNT_DATA_INO;
                    (*(*cli).fds.add(fd)).offset = 0;
                    (*(*cli).fds.add(fd)).dir_cursor = 0;
                    (*(*cli).fds.add(fd)).sock_id = remote_ino as u32;
                    (*(*cli).fds.add(fd)).dev_type = mount_idx as u8;
                    (*(*cli).fds.add(fd)).flags = 0;
                    (*(*cli).fds.add(fd)).mount_batch_count = 0;
                    (*(*cli).fds.add(fd)).mount_batch_index = 0;
                    (*(*cli).fds.add(fd)).mount_batch_next_cursor = 0;
                    (*reply).label = SALTY_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = fd as u64;
                    return;
                }
            }
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        let inode = resolve_path(path_ptr, path_len);
        let is_dir = if inode.is_null() {
            false
        } else if (*inode).ftype == FTYPE_DIRECTORY {
            true
        } else if (*inode).ftype == FTYPE_MOUNT_POINT {
            true
        } else if (*inode).ftype == FTYPE_PROC_FILE
            && ((*inode).dev_type == PROC_FILE_ROOT || (*inode).dev_type == PROC_FILE_PID_DIR)
        {
            true
        } else {
            false
        };
        if !is_dir {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        // If the resolved inode is a mount point, open it as a mount dir
        if (*inode).ftype == FTYPE_MOUNT_POINT {
            for i in 0..MAX_MOUNTS {
                let m = &*(&raw const MOUNTS[i]);
                if m.active != 0 && m.mount_ino == (*inode).ino {
                    let cli = get_client(badge);
                    if cli.is_null() {
                        (*reply).label = SALTY_OUT_OF_MEMORY;
                        return;
                    }
                    for fd in 0..(*cli).fds_cap as usize {
                        if (*(*cli).fds.add(fd)).active == 0 {
                            (*(*cli).fds.add(fd)).active = 1;
                            (*(*cli).fds.add(fd)).fd_type = FD_TYPE_MOUNT;
                            (*(*cli).fds.add(fd)).inode = (*inode).ino;
                            (*(*cli).fds.add(fd)).offset = 0;
                            (*(*cli).fds.add(fd)).dir_cursor = 0;
                            (*(*cli).fds.add(fd)).sock_id = m.root_ino;
                            (*(*cli).fds.add(fd)).dev_type = i as u8;
                            (*(*cli).fds.add(fd)).flags = 0;
                            (*(*cli).fds.add(fd)).mount_batch_count = 0;
                            (*(*cli).fds.add(fd)).mount_batch_index = 0;
                            (*(*cli).fds.add(fd)).mount_batch_next_cursor = 0;
                            (*reply).label = SALTY_OK;
                            (*reply).length = 1;
                            (*reply).regs[0] = fd as u64;
                            return;
                        }
                    }
                    (*reply).label = SALTY_OUT_OF_MEMORY;
                    return;
                }
            }
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        for fd in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(fd)).active == 0 {
                (*(*cli).fds.add(fd)).active = 1;
                (*(*cli).fds.add(fd)).fd_type = FD_TYPE_DIR;
                (*(*cli).fds.add(fd)).inode = (*inode).ino;
                (*(*cli).fds.add(fd)).offset = 0;
                (*(*cli).fds.add(fd)).dir_cursor = 0;
                inode_open((*inode).ino);
                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = fd as u64;
                return;
            }
        }

        (*reply).label = SALTY_OUT_OF_MEMORY;
    }
}

unsafe fn handle_readdir(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;

        let cli = get_client(badge);
        if cli.is_null()
            || fd < 0
            || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_DIR
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let dir = inode_by_ino((*(*cli).fds.add(fd as usize)).inode);
        if dir.is_null() {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // /proc virtual directories
        if (*dir).ftype == FTYPE_PROC_FILE {
            let cursor = (*(*cli).fds.add(fd as usize)).dir_cursor;
            handle_proc_readdir(dir, cursor, reply);
            if (*reply).label == SALTY_OK && (*reply).regs[0] != 0 {
                // Advance cursor: use regs[1] (next cursor) if set by proc_readdir
                (*(*cli).fds.add(fd as usize)).dir_cursor = (*reply).regs[1] as u32;
                (*reply).regs[1] = 0; // clear before returning to client
            }
            return;
        }

        let cursor = (*(*cli).fds.add(fd as usize)).dir_cursor;
        for i in (cursor as usize)..(*dir).dirents_cap as usize {
            if (*(*dir).dirents.add(i)).active != 0 {
                let child = inode_by_ino((*(*dir).dirents.add(i)).ino);
                let d_type: u8 = if !child.is_null() {
                    match (*child).ftype {
                        FTYPE_REGULAR => 8,     // DT_REG
                        FTYPE_DIRECTORY => 4,   // DT_DIR
                        FTYPE_CHAR_DEVICE => 2, // DT_CHR
                        FTYPE_SYMLINK => 10,    // DT_LNK
                        FTYPE_PROC_FILE => 4,   // DT_DIR (proc virtual dir)
                        FTYPE_MOUNT_POINT => 4, // DT_DIR (mount point)
                        _ => 0,
                    }
                } else {
                    0
                };

                let name_len = (*(*dir).dirents.add(i)).name_len;
                (*reply).label = SALTY_OK;
                (*reply).length = 5 + ((name_len as u64 + 7) / 8);
                (*reply).regs[0] = name_len as u64;
                (*reply).regs[1] = 0; // reserved
                (*reply).regs[2] = (*(*dir).dirents.add(i)).ino as u64;
                (*reply).regs[3] = d_type as u64;

                for j in 4..20 {
                    (*reply).regs[j] = 0;
                }
                let dst = &raw mut (*reply).regs[4] as *mut u8;
                for j in 0..name_len as usize {
                    *dst.add(j) = (*(*dir).dirents.add(i)).name[j];
                }

                (*(*cli).fds.add(fd as usize)).dir_cursor = (i + 1) as u32;
                return;
            }
        }

        // End of directory
        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = 0;
    }
}

// ======================================================================
// Socket helpers
// ======================================================================

unsafe fn alloc_socket() -> *mut SocketState {
    unsafe {
        for i in 0..max_sockets() {
            if SOCKETS!()[i].active == 0 {
                let s = &raw mut SOCKETS!()[i];
                (*s).active = 1;
                (*s).sock_id = NEXT_SOCK_ID;
                NEXT_SOCK_ID += 1;
                (*s).state = SOCK_UNBOUND;
                (*s).bound_ino = 0;
                (*s).backlog = 0;
                (*s).pending_count = 0;
                // Allocate pending array if not yet allocated
                if (*s).pending.is_null() {
                    let ptr = vfs_alloc_array::<PendingConn>(INITIAL_PENDING_CONN);
                    if ptr.is_null() {
                        (*s).active = 0;
                        return core::ptr::null_mut();
                    }
                    (*s).pending = ptr;
                    (*s).pending_cap = INITIAL_PENDING_CONN as u8;
                }
                for j in 0..(*s).pending_cap as usize { (*(*s).pending.add(j)).active = 0; }
                (*s).peer_sock_id = 0;
                (*s).peer_badge = 0;
                (*s).data_head = 0;
                (*s).data_tail = 0;
                (*s).accept_reply_slot = 0;
                (*s).accept_badge = 0;
                (*s).recv_reply_slot = 0;
                (*s).recv_badge = 0;
                (*s).pending_cap_count = 0;
                (*s).shut_rd = 0;
                (*s).shut_wr = 0;
                (*s).peer_closed = 0;
                (*s).refcount = 1;
                return s;
            }
        }
        // No free slot: grow the pool and retry
        if vfs_grow_pool(
            &raw mut SOCKETS_PTR as *mut *mut u8,
            &raw mut SOCKETS_CAP,
            core::mem::size_of::<SocketState>(),
        ) != 0 {
            return core::ptr::null_mut();
        }
        alloc_socket()
    }
}

unsafe fn find_socket(sock_id: u32) -> *mut SocketState {
    unsafe {
        for i in 0..max_sockets() {
            if SOCKETS!()[i].active != 0 && SOCKETS!()[i].sock_id == sock_id {
                return &raw mut SOCKETS!()[i];
            }
        }
        core::ptr::null_mut()
    }
}

unsafe fn sock_buf_len(s: *const SocketState) -> u16 {
    unsafe {
        let h = (*s).data_head;
        let t = (*s).data_tail;
        if h >= t { h - t } else { SOCK_BUF_SIZE as u16 - t + h }
    }
}

unsafe fn sock_buf_free(s: *const SocketState) -> u16 {
    (SOCK_BUF_SIZE as u16 - 1) - unsafe { sock_buf_len(s) }
}

unsafe fn sock_buf_write(s: *mut SocketState, data: *const u8, len: u16) -> u16 {
    unsafe {
        let free = sock_buf_free(s);
        let actual = if len < free { len } else { free };
        for i in 0..actual as usize {
            (*s).data_buf[(*s).data_head as usize] = *data.add(i);
            (*s).data_head = ((*s).data_head + 1) % SOCK_BUF_SIZE as u16;
        }
        actual
    }
}

unsafe fn sock_buf_read(s: *mut SocketState, data: *mut u8, len: u16) -> u16 {
    unsafe {
        let avail = sock_buf_len(s);
        let actual = if len < avail { len } else { avail };
        for i in 0..actual as usize {
            *data.add(i) = (*s).data_buf[(*s).data_tail as usize];
            (*s).data_tail = ((*s).data_tail + 1) % SOCK_BUF_SIZE as u16;
        }
        actual
    }
}

unsafe fn alloc_reply_slot() -> u64 {
    unsafe {
        let slot = NEXT_REPLY_SLOT;
        NEXT_REPLY_SLOT += 1;
        if NEXT_REPLY_SLOT > CAP_REPLY_LIMIT {
            NEXT_REPLY_SLOT = CAP_REPLY_BASE;
        }
        slot
    }
}

/// Handle a deferred PTY device read. Called from main loop when fd is DEV_PTY_SLAVE.
/// Returns true if reply is deferred (skip_reply), false if reply is ready now.
unsafe fn handle_pty_dev_read(
    msg: *const SaltyMsg, fde: *mut FdEntry, reply: *mut SaltyMsg, badge: u64,
) -> bool {
    unsafe {
        let count = (*msg).regs[1];
        let max = if count > 152 { 152 } else { count };
        let pty_id = (*fde).sock_id as u64;

        // Try-read from ttyd (always returns immediately)
        let mut treq = SaltyMsg::zeroed();
        let mut treply = SaltyMsg::zeroed();
        treq.label = TTYD_PTY_READ;
        treq.regs[0] = pty_id;
        treq.regs[1] = max;
        treq.length = 2;

        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
        if err != 0 || treply.label != SALTY_OK {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        let actual = treply.regs[0];
        if actual > 0 {
            // Data available — return immediately
            (*reply).label = SALTY_OK;
            (*reply).length = 1 + (actual + 7) / 8;
            (*reply).regs[0] = actual;
            let src = &treply.regs[1] as *const u64 as *const u8;
            let dst = &raw mut (*reply).regs[1] as *mut u8;
            for i in 0..actual as usize {
                *dst.add(i) = *src.add(i);
            }
            return false;
        }

        // WOULD_BLOCK — save caller's reply cap, enqueue pending reader
        let pid = pty_id as usize;
        if pid >= MAX_PTYS || PTY_PENDING_COUNT[pid] >= MAX_PTY_WAITERS {
            (*reply).label = SALTY_BUSY;
            return false;
        }

        let slot = alloc_reply_slot();
        let save_err = salty::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if save_err != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        let idx = PTY_PENDING_COUNT[pid];
        PTY_PENDING[pid][idx] = PtyPendingReader {
            active: 1,
            badge,
            reply_slot: slot,
            max_count: max,
        };
        PTY_PENDING_COUNT[pid] += 1;

        true // deferred — VFS will wake this reader when ttyd signals data-ready
    }
}

/// Handle bound notification from ttyd signalling PTY data ready.
/// Called when VFS wakes from reply_recv with a notification (msg.length==0, badge!=0).
/// Wakes pending PTY readers by collecting data from ttyd and forwarding to saved reply caps.
unsafe fn handle_pty_notification(ntfn_badge: u64) {
    unsafe {
        for pty_id in 0..MAX_PTYS {
            if ntfn_badge & (1u64 << pty_id) == 0 {
                continue;
            }

            // Wake pending readers for this PTY in FIFO order
            while PTY_PENDING_COUNT[pty_id] > 0 {
                let reader = PTY_PENDING[pty_id][0];
                if reader.active == 0 {
                    break;
                }

                // Collect data from ttyd
                let mut creq = SaltyMsg::zeroed();
                let mut creply = SaltyMsg::zeroed();
                creq.label = TTYD_PTY_COLLECT;
                creq.regs[0] = pty_id as u64;
                creq.regs[1] = reader.max_count;
                creq.length = 2;
                let cerr = ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const creq, &raw mut creply);

                let actual = creply.regs[0];
                if actual == 0 {
                    break; // buffer drained
                }

                // Forward data to saved client reply cap
                let mut wake = SaltyMsg::zeroed();
                wake.label = SALTY_OK;
                wake.length = 1 + (actual + 7) / 8;
                wake.regs[0] = actual;
                let src = &creply.regs[1] as *const u64 as *const u8;
                let dst = &raw mut wake.regs[1] as *mut u8;
                for i in 0..actual as usize {
                    *dst.add(i) = *src.add(i);
                }
                ipc::send_ctx(ipc_ctx(), reader.reply_slot, &raw const wake);

                // Shift remaining waiters forward (FIFO)
                for j in 1..PTY_PENDING_COUNT[pty_id] {
                    PTY_PENDING[pty_id][j - 1] = PTY_PENDING[pty_id][j];
                }
                PTY_PENDING_COUNT[pty_id] -= 1;
                if PTY_PENDING_COUNT[pty_id] < MAX_PTY_WAITERS {
                    PTY_PENDING[pty_id][PTY_PENDING_COUNT[pty_id]] = PtyPendingReader::zeroed();
                }
            }

            // Wake poll/epoll waiters for PTY fds (POLLIN event)
            // Iterate all clients to find PTY fds on this pty_id
            for ci in 0..max_clients() {
                let cli = &*(&raw const CLIENTS!()[ci]);
                if cli.active == 0 { continue; }
                for fi in 0..(*cli).fds_cap as usize {
                    if (*cli.fds.add(fi)).active != 0
                        && (*cli.fds.add(fi)).fd_type == FD_TYPE_DEVICE
                        && (*cli.fds.add(fi)).dev_type == DEV_PTY_SLAVE
                        && (*cli.fds.add(fi)).sock_id as usize == pty_id
                    {
                        wake_poll_waiters(cli.badge, fi as i32, 0x001); // POLLIN
                    }
                }
            }
        }
    }
}

/// Wake poll waiters that match a given fd for a given badge.
/// When fd == -1, broadcast: wake waiter for ANY fd with matching requested events.
unsafe fn wake_poll_waiters(badge: u64, fd: i32, revents: u16) {
    unsafe {
        for i in 0..max_poll_waiters() {
            if POLL_WAITERS!()[i].active == 0 || POLL_WAITERS!()[i].badge != badge {
                continue;
            }
            if fd == -1 {
                // Broadcast: report revents on all fds that requested matching events
                let mut wake_reply = SaltyMsg::zeroed();
                wake_reply.label = SALTY_OK;
                let mut ready_count: u64 = 0;
                for j in 0..POLL_WAITERS!()[i].nfds as usize {
                    let requested = POLL_WAITERS!()[i].fds[j].1;
                    // POLLHUP/POLLERR always reported regardless of requested events
                    let matched = revents & (requested | 0x010 | 0x008);
                    if matched != 0 {
                        wake_reply.regs[1 + j] = matched as u64;
                        ready_count += 1;
                    }
                }
                if ready_count > 0 {
                    wake_reply.regs[0] = ready_count;
                    wake_reply.length = 1 + POLL_WAITERS!()[i].nfds as u64;
                    ipc::send_ctx(ipc_ctx(), POLL_WAITERS!()[i].reply_slot, &raw const wake_reply);
                    POLL_WAITERS!()[i].active = 0;
                }
            } else {
                // Targeted: match specific fd
                for j in 0..POLL_WAITERS!()[i].nfds as usize {
                    if POLL_WAITERS!()[i].fds[j].0 == fd {
                        let mut wake_reply = SaltyMsg::zeroed();
                        wake_reply.label = SALTY_OK;
                        wake_reply.regs[0] = 1;
                        wake_reply.regs[1 + j] = revents as u64;
                        wake_reply.length = 1 + POLL_WAITERS!()[i].nfds as u64;
                        ipc::send_ctx(ipc_ctx(), POLL_WAITERS!()[i].reply_slot, &raw const wake_reply);
                        POLL_WAITERS!()[i].active = 0;
                        break;
                    }
                }
            }
        }
    }
}

// ======================================================================
// Pipe helpers
// ======================================================================

unsafe fn find_pipe(pipe_id: u32) -> *mut PipeState {
    unsafe {
        for i in 0..max_pipes() {
            if PIPES!()[i].active != 0 && PIPES!()[i].pipe_id == pipe_id {
                return &raw mut PIPES!()[i];
            }
        }
        core::ptr::null_mut()
    }
}

unsafe fn alloc_pipe() -> *mut PipeState {
    unsafe {
        for i in 0..max_pipes() {
            if PIPES!()[i].active == 0 {
                let p = &raw mut PIPES!()[i];
                (*p).active = 1;
                (*p).pipe_id = NEXT_PIPE_ID;
                NEXT_PIPE_ID += 1;
                (*p).read_refcount = 1;
                (*p).write_refcount = 1;
                (*p).data_head = 0;
                (*p).data_tail = 0;
                (*p).recv_waiter_count = 0;
                (*p).write_waiter_count = 0;
                // Allocate waiter arrays if not yet allocated
                if (*p).recv_waiters.is_null() {
                    let rw = vfs_alloc_array::<PipeReadWaiter>(INITIAL_PIPE_WAITERS);
                    let ww = vfs_alloc_array::<PipeWriteWaiter>(INITIAL_PIPE_WAITERS);
                    if rw.is_null() || ww.is_null() {
                        (*p).active = 0;
                        return core::ptr::null_mut();
                    }
                    (*p).recv_waiters = rw;
                    (*p).recv_waiter_cap = INITIAL_PIPE_WAITERS as u8;
                    (*p).write_waiters = ww;
                    (*p).write_waiter_cap = INITIAL_PIPE_WAITERS as u8;
                }
                return p;
            }
        }
        // No free slot: grow the pool and retry
        if vfs_grow_pool(
            &raw mut PIPES_PTR as *mut *mut u8,
            &raw mut PIPES_CAP,
            core::mem::size_of::<PipeState>(),
        ) != 0 {
            return core::ptr::null_mut();
        }
        alloc_pipe()
    }
}

unsafe fn pipe_buf_len(p: *const PipeState) -> u16 {
    unsafe {
        let h = (*p).data_head;
        let t = (*p).data_tail;
        if h >= t { h - t } else { PIPE_BUF_SIZE as u16 - t + h }
    }
}

unsafe fn pipe_buf_free(p: *const PipeState) -> u16 {
    (PIPE_BUF_SIZE as u16 - 1) - unsafe { pipe_buf_len(p) }
}

unsafe fn pipe_buf_write(p: *mut PipeState, data: *const u8, len: u16) -> u16 {
    unsafe {
        let free = pipe_buf_free(p);
        let actual = if len < free { len } else { free };
        for i in 0..actual as usize {
            (*p).data_buf[(*p).data_head as usize] = *data.add(i);
            (*p).data_head = ((*p).data_head + 1) % PIPE_BUF_SIZE as u16;
        }
        actual
    }
}

unsafe fn pipe_buf_read(p: *mut PipeState, data: *mut u8, len: u16) -> u16 {
    unsafe {
        let avail = pipe_buf_len(p);
        let actual = if len < avail { len } else { avail };
        for i in 0..actual as usize {
            *data.add(i) = (*p).data_buf[(*p).data_tail as usize];
            (*p).data_tail = ((*p).data_tail + 1) % PIPE_BUF_SIZE as u16;
        }
        actual
    }
}

/// Push a read waiter onto the pipe's FIFO queue. Returns false if full.
unsafe fn pipe_push_recv_waiter(pipe: *mut PipeState, slot: u64, badge: u64, req_len: u16) -> bool {
    unsafe {
        let count = (*pipe).recv_waiter_count as usize;
        if count >= (*pipe).recv_waiter_cap as usize { return false; }
        (*(*pipe).recv_waiters.add(count)).reply_slot = slot;
        (*(*pipe).recv_waiters.add(count)).badge = badge;
        (*(*pipe).recv_waiters.add(count)).requested_len = req_len;
        (*pipe).recv_waiter_count = (count + 1) as u8;
        true
    }
}

/// Pop the first read waiter from the pipe's FIFO queue.
unsafe fn pipe_pop_recv_waiter(pipe: *mut PipeState) -> Option<PipeReadWaiter> {
    unsafe {
        let count = (*pipe).recv_waiter_count as usize;
        if count == 0 { return None; }
        let waiter = *(*pipe).recv_waiters.add(0);
        // Shift remaining waiters down
        for i in 1..count {
            *(*pipe).recv_waiters.add(i - 1) = *(*pipe).recv_waiters.add(i);
        }
        *(*pipe).recv_waiters.add(count - 1) = PipeReadWaiter::zeroed();
        (*pipe).recv_waiter_count = (count - 1) as u8;
        Some(waiter)
    }
}

/// Push a write waiter onto the pipe's FIFO queue with saved data. Returns false if full.
unsafe fn pipe_push_write_waiter(pipe: *mut PipeState, slot: u64, badge: u64, src: *const u8, len: u16) -> bool {
    unsafe {
        let count = (*pipe).write_waiter_count as usize;
        if count >= (*pipe).write_waiter_cap as usize { return false; }
        (*(*pipe).write_waiters.add(count)).reply_slot = slot;
        (*(*pipe).write_waiters.add(count)).badge = badge;
        (*(*pipe).write_waiters.add(count)).data_len = len;
        let actual = if len > 144 { 144 } else { len };
        for i in 0..actual as usize {
            (*(*pipe).write_waiters.add(count)).data[i] = *src.add(i);
        }
        (*pipe).write_waiter_count = (count + 1) as u8;
        true
    }
}

/// Pop the first write waiter from the pipe's FIFO queue.
unsafe fn pipe_pop_write_waiter(pipe: *mut PipeState) -> Option<PipeWriteWaiter> {
    unsafe {
        let count = (*pipe).write_waiter_count as usize;
        if count == 0 { return None; }
        let waiter = *(*pipe).write_waiters.add(0);
        // Shift remaining waiters down
        for i in 1..count {
            *(*pipe).write_waiters.add(i - 1) = *(*pipe).write_waiters.add(i);
        }
        *(*pipe).write_waiters.add(count - 1) = PipeWriteWaiter::zeroed();
        (*pipe).write_waiter_count = (count - 1) as u8;
        Some(waiter)
    }
}

/// Close a pipe FD — decrement refcount, wake blocked peers, free if both zero.
unsafe fn close_pipe(fde: *mut FdEntry) {
    unsafe {
        let pipe = find_pipe((*fde).pipe_id());
        if pipe.is_null() { return; }

        let is_read_end = ((*fde).flags & O_ACCMODE) == 0; // O_RDONLY = 0
        if is_read_end {
            (*pipe).read_refcount = (*pipe).read_refcount.saturating_sub(1);
            // No readers left — wake ALL blocked writers with EPIPE
            if (*pipe).read_refcount == 0 {
                while let Some(w) = pipe_pop_write_waiter(pipe) {
                    let mut wake = SaltyMsg::zeroed();
                    wake.label = SALTY_INVALID_OPERATION; // EPIPE
                    ipc::send_ctx(ipc_ctx(), w.reply_slot, &raw const wake);
                }
                wake_poll_waiters_pipe(pipe, false, 0x008); // POLLERR on write end
            }
        } else {
            (*pipe).write_refcount = (*pipe).write_refcount.saturating_sub(1);
            // No writers left — wake ALL blocked readers with EOF
            if (*pipe).write_refcount == 0 {
                while let Some(w) = pipe_pop_recv_waiter(pipe) {
                    let mut wake = SaltyMsg::zeroed();
                    wake.label = SALTY_OK;
                    wake.length = 1;
                    wake.regs[0] = 0; // EOF
                    ipc::send_ctx(ipc_ctx(), w.reply_slot, &raw const wake);
                }
                wake_poll_waiters_pipe(pipe, true, 0x010); // POLLHUP on read end
            }
        }

        // Free pipe if both ends closed
        if (*pipe).read_refcount == 0 && (*pipe).write_refcount == 0 {
            (*pipe).active = 0;
        }
    }
}

/// Wake poll waiters for any fd that is a pipe end matching the given pipe.
/// `is_read_end`: true = wake waiters on read-end fds, false = wake waiters on write-end fds.
unsafe fn wake_poll_waiters_pipe(pipe: *const PipeState, is_read_end: bool, revents: u16) {
    unsafe {
        let pipe_id = (*pipe).pipe_id;
        for i in 0..max_poll_waiters() {
            if POLL_WAITERS!()[i].active == 0 { continue; }
            let badge = POLL_WAITERS!()[i].badge;
            let cli = get_client_noalloc(badge);
            if cli.is_null() { continue; }

            let mut ready_count: u64 = 0;
            let mut wake_reply = SaltyMsg::zeroed();
            wake_reply.label = SALTY_OK;

            for j in 0..POLL_WAITERS!()[i].nfds as usize {
                let pfd = POLL_WAITERS!()[i].fds[j].0;
                if pfd < 0 || pfd >= (*cli).fds_cap as i32 { continue; }
                let fde = *(*cli).fds.add(pfd as usize);
                if fde.active == 0 || fde.fd_type != FD_TYPE_PIPE { continue; }
                if fde.pipe_id() != pipe_id { continue; }
                let fd_is_read = (fde.flags & O_ACCMODE) == 0;
                if fd_is_read != is_read_end { continue; }

                let requested = POLL_WAITERS!()[i].fds[j].1;
                let matched = revents & (requested | 0x010 | 0x008);
                if matched != 0 {
                    wake_reply.regs[1 + j] = matched as u64;
                    ready_count += 1;
                }
            }

            if ready_count > 0 {
                wake_reply.regs[0] = ready_count;
                wake_reply.length = 1 + POLL_WAITERS!()[i].nfds as u64;
                ipc::send_ctx(ipc_ctx(), POLL_WAITERS!()[i].reply_slot, &raw const wake_reply);
                POLL_WAITERS!()[i].active = 0;
            }
        }
    }
}

/// Look up client without allocating a new one if not found.
unsafe fn get_client_noalloc(badge: u64) -> *mut ClientState {
    unsafe {
        for i in 0..max_clients() {
            if CLIENTS!()[i].active != 0 && CLIENTS!()[i].badge == badge {
                return &raw mut CLIENTS!()[i];
            }
        }
        core::ptr::null_mut()
    }
}

// ======================================================================
// Pipe request handlers
// ======================================================================

/// handle_pipe: create a pipe pair, return read_fd and write_fd
unsafe fn handle_pipe(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let flags = (*msg).regs[0] as u32;

        let pipe = alloc_pipe();
        if pipe.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        let cli = get_client(badge);
        if cli.is_null() {
            (*pipe).active = 0;
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // Allocate read-end fd
        let mut read_fd: i32 = -1;
        for i in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(i)).active == 0 {
                read_fd = i as i32;
                break;
            }
        }
        if read_fd < 0 {
            (*pipe).active = 0;
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // Allocate write-end fd
        let mut write_fd: i32 = -1;
        for i in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(i)).active == 0 && i as i32 != read_fd {
                write_fd = i as i32;
                break;
            }
        }
        if write_fd < 0 {
            (*pipe).active = 0;
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // Set up read-end fd
        (*(*cli).fds.add(read_fd as usize)).active = 1;
        (*(*cli).fds.add(read_fd as usize)).fd_type = FD_TYPE_PIPE;
        (*(*cli).fds.add(read_fd as usize)).sock_id = (*pipe).pipe_id; // reuse sock_id for pipe_id
        (*(*cli).fds.add(read_fd as usize)).flags = if flags & 0x0800 != 0 { 0x0800u32 } else { 0 }; // O_NONBLOCK on read end
        (*(*cli).fds.add(read_fd as usize)).offset = 0;

        // Set up write-end fd
        (*(*cli).fds.add(write_fd as usize)).active = 1;
        (*(*cli).fds.add(write_fd as usize)).fd_type = FD_TYPE_PIPE;
        (*(*cli).fds.add(write_fd as usize)).sock_id = (*pipe).pipe_id;
        (*(*cli).fds.add(write_fd as usize)).flags = O_WRONLY | (if flags & 0x0800 != 0 { 0x0800u32 } else { 0 }); // O_WRONLY + O_NONBLOCK
        (*(*cli).fds.add(write_fd as usize)).offset = 0;

        // O_CLOEXEC
        if flags & 0x80000 != 0 {
            *(*cli).fd_flags.add(read_fd as usize) = 1;  // FD_CLOEXEC
            *(*cli).fd_flags.add(write_fd as usize) = 1;
        }

        (*reply).label = SALTY_OK;
        (*reply).length = 2;
        (*reply).regs[0] = read_fd as u64;
        (*reply).regs[1] = write_fd as u64;
    }
}

/// Handle read on a pipe fd
unsafe fn handle_pipe_read(msg: *const SaltyMsg, fde: *mut FdEntry, reply: *mut SaltyMsg, badge: u64) -> bool {
    unsafe {
        // Bug 6: Verify read-end access mode
        if ((*fde).flags & O_ACCMODE) != 0 {
            // Not O_RDONLY — reject read on write-end
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let pipe = find_pipe((*fde).pipe_id());
        if pipe.is_null() {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        // Bug 1: Respect requested length from msg
        let requested = (*msg).regs[1] as u16;
        let avail = pipe_buf_len(pipe);
        if avail > 0 {
            let mut count = avail;
            if requested > 0 && requested < count { count = requested; }
            if count > 152 { count = 152; }
            let dst = &raw mut (*reply).regs[1] as *mut u8;
            let actual = pipe_buf_read(pipe, dst, count);
            (*reply).label = SALTY_OK;
            (*reply).length = 1 + ((actual as u64 + 7) / 8);
            (*reply).regs[0] = actual as u64;

            // Bug 2+7: Wake blocked writer — write their saved data into buffer
            if let Some(w) = pipe_pop_write_waiter(pipe) {
                let written = pipe_buf_write(pipe, w.data.as_ptr(), w.data_len);
                let mut wake = SaltyMsg::zeroed();
                wake.label = SALTY_OK;
                wake.length = 1;
                wake.regs[0] = written as u64;
                ipc::send_ctx(ipc_ctx(), w.reply_slot, &raw const wake);
            }

            // Wake poll waiters on write-end (POLLOUT — space available)
            wake_poll_waiters_pipe(pipe, false, 0x004);
            return false;
        }

        // Buffer empty
        if (*pipe).write_refcount == 0 {
            // No writers — return EOF
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return false;
        }

        // O_NONBLOCK: return EAGAIN instead of blocking
        if (*fde).flags & 0x0800 != 0 {
            (*reply).label = SALTY_WOULD_BLOCK;
            return false;
        }

        // Block reader — save caller (Bug 7: multi-waiter)
        let slot = alloc_reply_slot();
        let err = salty::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if err != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }
        let req_len = if requested > 0 && requested < 152 { requested } else { 152 };
        if !pipe_push_recv_waiter(pipe, slot, badge, req_len) {
            // Waiter queue full — return EAGAIN
            (*reply).label = SALTY_WOULD_BLOCK;
            return false;
        }
        true // deferred
    }
}

/// Handle write on a pipe fd
unsafe fn handle_pipe_write(msg: *const SaltyMsg, fde: *mut FdEntry, reply: *mut SaltyMsg, badge: u64) -> bool {
    unsafe {
        // Bug 6: Verify write-end access mode
        if ((*fde).flags & O_ACCMODE) != O_WRONLY {
            // Not O_WRONLY — reject write on read-end
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let pipe = find_pipe((*fde).pipe_id());
        if pipe.is_null() {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        // No readers — EPIPE
        if (*pipe).read_refcount == 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        let count = (*msg).regs[1];
        let src = &(*msg).regs[2] as *const u64 as *const u8;
        let mut actual_count = count;
        if actual_count > 144 { actual_count = 144; }

        let free = pipe_buf_free(pipe);
        if free == 0 {
            // O_NONBLOCK: return EAGAIN instead of blocking
            if (*fde).flags & 0x0800 != 0 {
                (*reply).label = SALTY_WOULD_BLOCK;
                return false;
            }

            // Buffer full — block writer with saved data (Bug 2+7: multi-waiter)
            let slot = alloc_reply_slot();
            let err = salty::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
            if err != 0 {
                (*reply).label = SALTY_INVALID_OPERATION;
                return false;
            }
            if !pipe_push_write_waiter(pipe, slot, badge, src, actual_count as u16) {
                // Waiter queue full — return EAGAIN
                (*reply).label = SALTY_WOULD_BLOCK;
                return false;
            }
            return true; // deferred
        }

        let written = pipe_buf_write(pipe, src, actual_count as u16);

        // Bug 7: Wake blocked reader — pop from multi-waiter queue
        if written > 0 {
            if let Some(w) = pipe_pop_recv_waiter(pipe) {
                let mut wake = SaltyMsg::zeroed();
                let avail = pipe_buf_len(pipe);
                let mut rcount = avail;
                if w.requested_len > 0 && w.requested_len < rcount { rcount = w.requested_len; }
                if rcount > 152 { rcount = 152; }
                let dst = &raw mut wake.regs[1] as *mut u8;
                let actual = pipe_buf_read(pipe, dst, rcount);
                wake.label = SALTY_OK;
                wake.length = 1 + ((actual as u64 + 7) / 8);
                wake.regs[0] = actual as u64;
                ipc::send_ctx(ipc_ctx(), w.reply_slot, &raw const wake);
            }
        }

        // Wake poll waiters on read-end (POLLIN — data available)
        if written > 0 {
            wake_poll_waiters_pipe(pipe, true, 0x001);
        }

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = written as u64;
        false
    }
}

// ======================================================================
// Dup/dup2 handlers
// ======================================================================

unsafe fn handle_dup(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let oldfd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null() || oldfd < 0 || oldfd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(oldfd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Find lowest free fd
        let mut newfd: i32 = -1;
        for i in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(i)).active == 0 {
                newfd = i as i32;
                break;
            }
        }
        if newfd < 0 {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        dup_fd_entry(cli, oldfd, newfd);

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = newfd as u64;
    }
}

unsafe fn handle_dup2(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let oldfd = (*msg).regs[0] as i32;
        let newfd = (*msg).regs[1] as i32;
        let cli = get_client(badge);
        if cli.is_null() || oldfd < 0 || oldfd >= (*cli).fds_cap as i32
            || newfd < 0 || newfd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(oldfd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        if oldfd == newfd {
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = newfd as u64;
            return;
        }

        // Close newfd if open
        if (*(*cli).fds.add(newfd as usize)).active != 0 {
            let fde = (*cli).fds.add(newfd as usize);
            if (*fde).fd_type == FD_TYPE_SOCKET {
                close_socket(fde);
            } else if (*fde).fd_type == FD_TYPE_PIPE {
                close_pipe(fde);
            } else {
                inode_close((*fde).inode);
            }
            (*(*cli).fds.add(newfd as usize)).active = 0;
        }

        dup_fd_entry(cli, oldfd, newfd);

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = newfd as u64;
    }
}

unsafe fn handle_dup3(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let oldfd = (*msg).regs[0] as i32;
        let newfd = (*msg).regs[1] as i32;
        let flags = (*msg).regs[2] as u32;
        let cli = get_client(badge);
        if cli.is_null() || oldfd < 0 || oldfd >= (*cli).fds_cap as i32
            || newfd < 0 || newfd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(oldfd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // dup3: oldfd == newfd is an error (unlike dup2)
        if oldfd == newfd {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Close newfd if open
        if (*(*cli).fds.add(newfd as usize)).active != 0 {
            let fde = (*cli).fds.add(newfd as usize);
            if (*fde).fd_type == FD_TYPE_SOCKET {
                close_socket(fde);
            } else if (*fde).fd_type == FD_TYPE_PIPE {
                close_pipe(fde);
            } else {
                inode_close((*fde).inode);
            }
            (*(*cli).fds.add(newfd as usize)).active = 0;
        }

        dup_fd_entry(cli, oldfd, newfd);

        // Apply flags (O_CLOEXEC = 0x80000)
        if flags & 0x80000 != 0 {
            *(*cli).fd_flags.add(newfd as usize) = 1; // FD_CLOEXEC
        } else {
            *(*cli).fd_flags.add(newfd as usize) = 0;
        }

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = newfd as u64;
    }
}

/// Copy fd entry and increment refcounts as needed.
unsafe fn dup_fd_entry(cli: *mut ClientState, oldfd: i32, newfd: i32) {
    unsafe {
        *(*cli).fds.add(newfd as usize) = *(*cli).fds.add(oldfd as usize);
        let fde = *(*cli).fds.add(newfd as usize);
        if fde.fd_type == FD_TYPE_PIPE {
            let pipe = find_pipe(fde.pipe_id());
            if !pipe.is_null() {
                let is_read = (fde.flags & O_ACCMODE) == 0;
                if is_read {
                    (*pipe).read_refcount += 1;
                } else {
                    (*pipe).write_refcount += 1;
                }
            }
        } else if fde.fd_type == FD_TYPE_SOCKET {
            let sock = find_socket(fde.sock_id);
            if !sock.is_null() {
                (*sock).refcount += 1;
            }
        } else {
            inode_open(fde.inode);
        }
    }
}

// ======================================================================
// Fork FD inheritance (VFS_CLONE_FDS)
// ======================================================================

unsafe fn handle_clone_fds(msg: *const SaltyMsg, reply: *mut SaltyMsg) {
    unsafe {
        let parent_badge = (*msg).regs[0];
        let child_badge = (*msg).regs[1];

        let parent = get_client_noalloc(parent_badge);
        if parent.is_null() {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let child = get_client(child_badge);
        if child.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // If parent has more FDs than child, grow child's FD table to match
        if (*parent).fds_cap > (*child).fds_cap {
            let required = (*parent).fds_cap as usize;
            let (new_fds, new_cap) = vfs_grow_array_with_min(
                (*child).fds,
                (*child).fds_cap as usize,
                required,
            );
            let (new_flags, _) = vfs_grow_array_with_min(
                (*child).fd_flags,
                (*child).fds_cap as usize,
                required,
            );
            if new_fds.is_null() || new_flags.is_null() {
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }
            (*child).fds = new_fds;
            (*child).fd_flags = new_flags;
            (*child).fds_cap = new_cap as u16;
        }

        // Copy all FDs from parent to child
        for i in 0..(*parent).fds_cap as usize {
            *(*child).fds.add(i) = *(*parent).fds.add(i);
            *(*child).fd_flags.add(i) = *(*parent).fd_flags.add(i);
            if (*(*child).fds.add(i)).active == 0 { continue; }
            // Increment pipe refcounts
            if (*(*child).fds.add(i)).fd_type == FD_TYPE_PIPE {
                let pipe = find_pipe((*(*child).fds.add(i)).pipe_id());
                if !pipe.is_null() {
                    let is_read = ((*(*child).fds.add(i)).flags & O_ACCMODE) == 0;
                    if is_read {
                        (*pipe).read_refcount += 1;
                    } else {
                        (*pipe).write_refcount += 1;
                    }
                }
            }
            // Increment socket refcounts
            if (*(*child).fds.add(i)).fd_type == FD_TYPE_SOCKET {
                let sock = find_socket((*(*child).fds.add(i)).sock_id);
                if !sock.is_null() {
                    (*sock).refcount += 1;
                }
            }
            // Increment inode open count for inode-based FDs
            if (*(*child).fds.add(i)).fd_type != FD_TYPE_PIPE
                && (*(*child).fds.add(i)).fd_type != FD_TYPE_SOCKET
            {
                inode_open((*(*child).fds.add(i)).inode);
            }
        }

        // Copy cwd
        let mut i = 0;
        while i < 128 {
            (*child).cwd[i] = (*parent).cwd[i];
            i += 1;
        }

        (*reply).label = SALTY_OK;
    }
}

#[inline(always)]
unsafe fn send_client_exit_error(reply_slot: u64) {
    unsafe {
        if reply_slot == 0 {
            return;
        }
        let mut wake = SaltyMsg::zeroed();
        wake.label = SALTY_INVALID_OPERATION;
        ipc::send_ctx(ipc_ctx(), reply_slot, &raw const wake);
    }
}

unsafe fn purge_poll_waiters_by_badge(dead_badge: u64) {
    unsafe {
        for i in 0..max_poll_waiters() {
            if POLL_WAITERS!()[i].active == 0 || POLL_WAITERS!()[i].badge != dead_badge {
                continue;
            }
            send_client_exit_error(POLL_WAITERS!()[i].reply_slot);
            POLL_WAITERS!()[i] = PollWaiter::zeroed();
        }
    }
}

unsafe fn purge_pty_waiters_by_badge(dead_badge: u64) {
    unsafe {
        for pty in 0..MAX_PTYS {
            let mut r = 0usize;
            while r < PTY_PENDING_COUNT[pty] {
                let ent = PTY_PENDING[pty][r];
                if ent.active == 0 || ent.badge != dead_badge {
                    r += 1;
                    continue;
                }
                send_client_exit_error(ent.reply_slot);
                for j in (r + 1)..PTY_PENDING_COUNT[pty] {
                    PTY_PENDING[pty][j - 1] = PTY_PENDING[pty][j];
                }
                PTY_PENDING_COUNT[pty] -= 1;
                PTY_PENDING[pty][PTY_PENDING_COUNT[pty]] = PtyPendingReader::zeroed();
            }
        }
    }
}

unsafe fn purge_pipe_waiters_by_badge(pipe: *mut PipeState, dead_badge: u64) {
    unsafe {
        let recv_count = (*pipe).recv_waiter_count as usize;
        let mut recv_dst = 0usize;
        for i in 0..recv_count {
            let w = *(*pipe).recv_waiters.add(i);
            if w.badge == dead_badge {
                send_client_exit_error(w.reply_slot);
            } else {
                *(*pipe).recv_waiters.add(recv_dst) = w;
                recv_dst += 1;
            }
        }
        let recv_kept = recv_dst as u8;
        while recv_dst < (*pipe).recv_waiter_cap as usize {
            *(*pipe).recv_waiters.add(recv_dst) = PipeReadWaiter::zeroed();
            recv_dst += 1;
        }
        (*pipe).recv_waiter_count = recv_kept;

        let write_count = (*pipe).write_waiter_count as usize;
        let mut write_dst = 0usize;
        for i in 0..write_count {
            let w = *(*pipe).write_waiters.add(i);
            if w.badge == dead_badge {
                send_client_exit_error(w.reply_slot);
            } else {
                *(*pipe).write_waiters.add(write_dst) = w;
                write_dst += 1;
            }
        }
        let write_kept = write_dst as u8;
        while write_dst < (*pipe).write_waiter_cap as usize {
            *(*pipe).write_waiters.add(write_dst) = PipeWriteWaiter::zeroed();
            write_dst += 1;
        }
        (*pipe).write_waiter_count = write_kept;
    }
}

unsafe fn purge_socket_waiters_by_badge(sock: *mut SocketState, dead_badge: u64) {
    unsafe {
        if (*sock).accept_badge == dead_badge {
            send_client_exit_error((*sock).accept_reply_slot);
            (*sock).accept_reply_slot = 0;
            (*sock).accept_badge = 0;
        }
        if (*sock).recv_badge == dead_badge {
            send_client_exit_error((*sock).recv_reply_slot);
            (*sock).recv_reply_slot = 0;
            (*sock).recv_badge = 0;
        }
        let mut pending = 0u8;
        for i in 0..(*sock).pending_cap as usize {
            if (*(*sock).pending.add(i)).active != 0 && (*(*sock).pending.add(i)).client_badge == dead_badge {
                send_client_exit_error((*(*sock).pending.add(i)).reply_slot);
                *(*sock).pending.add(i) = PendingConn::zeroed();
            }
            if (*(*sock).pending.add(i)).active != 0 {
                pending = pending.saturating_add(1);
            }
        }
        (*sock).pending_count = pending;
    }
}

unsafe fn cleanup_client_state(dead_badge: u64) {
    unsafe {
        let cli = get_client_noalloc(dead_badge);
        if cli.is_null() {
            return;
        }

        // Clear all deferred waiters/callers tied to this badge before fd teardown.
        purge_poll_waiters_by_badge(dead_badge);
        purge_pty_waiters_by_badge(dead_badge);

        for i in 0..max_pipes() {
            if PIPES!()[i].active != 0 {
                purge_pipe_waiters_by_badge(&raw mut PIPES!()[i], dead_badge);
            }
        }

        for i in 0..max_sockets() {
            if SOCKETS!()[i].active != 0 {
                purge_socket_waiters_by_badge(&raw mut SOCKETS!()[i], dead_badge);
            }
        }

        // Close every open fd owned by the dead client to drop pipe/socket refs.
        for i in 0..(*cli).fds_cap as usize {
            let fde = (*cli).fds.add(i);
            if (*fde).active == 0 {
                continue;
            }
            match (*fde).fd_type {
                FD_TYPE_SOCKET => close_socket(fde),
                FD_TYPE_PIPE => close_pipe(fde),
                FD_TYPE_EPOLL => {
                    let ep_idx = (*fde).sock_id as usize;
                    if ep_idx < max_epoll_instances() {
                        EPOLLS!()[ep_idx].active = 0;
                    }
                }
                _ => {
                    // Decrement inode open_count; frees if nlink==0
                    if (*fde).inode != 0 {
                        inode_close((*fde).inode);
                    }
                }
            }
            *(*cli).fds.add(i) = FdEntry::zeroed();
            *(*cli).fd_flags.add(i) = 0;
        }

        // Defensive cleanup for leaked epoll instances.
        for i in 0..max_epoll_instances() {
            if EPOLLS!()[i].active != 0 && EPOLLS!()[i].owner_badge == dead_badge {
                EPOLLS!()[i] = EpollInstance::zeroed();
            }
        }

        // Notify ttyd to release any controlling terminal owned by this dead client.
        let mut treq = SaltyMsg::zeroed();
        let mut treply = SaltyMsg::zeroed();
        treq.label = TTYD_CLIENT_EXIT;
        treq.regs[0] = dead_badge;
        treq.length = 1;
        let _ = ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);

        (*cli) = ClientState::zeroed();
    }
}

unsafe fn handle_client_exit(msg: *const SaltyMsg, reply: *mut SaltyMsg) {
    unsafe {
        let dead_badge = (*msg).regs[0];
        cleanup_client_state(dead_badge);
        (*reply).label = SALTY_OK;
    }
}

// ======================================================================
// isatty / ioctl / fcntl / chdir / getcwd handlers
// ======================================================================

unsafe fn handle_isatty(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }

        let is_tty = if (*(*cli).fds.add(fd as usize)).fd_type == FD_TYPE_DEVICE
            && ((*(*cli).fds.add(fd as usize)).dev_type == DEV_CONSOLE
                || (*(*cli).fds.add(fd as usize)).dev_type == DEV_PTY_SLAVE)
        {
            1u64
        } else {
            0u64
        };

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = is_tty;
    }
}

/// Forward tcgetattr to ttyd (for PTY) or console server (for /dev/console)
unsafe fn handle_tcgetattr(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let fde = *(*cli).fds.add(fd as usize);
        if fde.fd_type != FD_TYPE_DEVICE {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        if fde.dev_type == DEV_PTY_SLAVE {
            // Forward to ttyd via TTYD_PTY_TCGETATTR
            let mut treq = SaltyMsg::zeroed();
            let mut treply = SaltyMsg::zeroed();
            treq.label = TTYD_PTY_TCGETATTR;
            treq.regs[0] = fde.sock_id as u64; // pty_id
            treq.length = 1;
            let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
            if err != 0 || treply.label != SALTY_OK {
                (*reply).label = SALTY_INVALID_OPERATION;
                return;
            }
            (*reply).label = SALTY_OK;
            (*reply).length = treply.length;
            for i in 0..treply.length as usize {
                (*reply).regs[i] = treply.regs[i];
            }
        } else if fde.dev_type == DEV_CONSOLE {
            // Forward to console server
            let mut creq = SaltyMsg::zeroed();
            let mut creply = SaltyMsg::zeroed();
            creq.label = CONSOLE_TCGETATTR;
            creq.length = 0;
            let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_CONSOLE_EP, &raw const creq, &raw mut creply);
            if err != 0 || creply.label != SALTY_OK {
                (*reply).label = SALTY_INVALID_OPERATION;
                return;
            }
            (*reply).label = SALTY_OK;
            (*reply).length = creply.length;
            for i in 0..creply.length as usize {
                (*reply).regs[i] = creply.regs[i];
            }
        } else {
            (*reply).label = SALTY_INVALID_OPERATION;
        }
    }
}

/// Forward tcsetattr to ttyd (for PTY) or console server (for /dev/console)
unsafe fn handle_tcsetattr(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let fde = *(*cli).fds.add(fd as usize);
        if fde.fd_type != FD_TYPE_DEVICE {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        if fde.dev_type == DEV_PTY_SLAVE {
            // Forward to ttyd via TTYD_PTY_TCSETATTR
            // msg layout: regs[0]=fd, regs[1]=action, regs[2..11]=termios data
            let mut treq = SaltyMsg::zeroed();
            let mut treply = SaltyMsg::zeroed();
            treq.label = TTYD_PTY_TCSETATTR;
            treq.regs[0] = fde.sock_id as u64; // pty_id
            // Copy termios data from regs[1..] (action + flags + c_cc)
            let copy_len = if (*msg).length > 1 { (*msg).length - 1 } else { 0 };
            for i in 0..copy_len as usize {
                treq.regs[i + 1] = (*msg).regs[i + 1];
            }
            treq.length = 1 + copy_len;
            let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
            if err != 0 || treply.label != SALTY_OK {
                (*reply).label = SALTY_INVALID_OPERATION;
                return;
            }
            (*reply).label = SALTY_OK;
            (*reply).length = 0;
        } else if fde.dev_type == DEV_CONSOLE {
            // Forward to console server
            let mut creq = SaltyMsg::zeroed();
            let mut creply = SaltyMsg::zeroed();
            creq.label = CONSOLE_TCSETATTR;
            creq.length = (*msg).length;
            for i in 0..(*msg).length as usize {
                creq.regs[i] = (*msg).regs[i];
            }
            let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_CONSOLE_EP, &raw const creq, &raw mut creply);
            if err != 0 || creply.label != SALTY_OK {
                (*reply).label = SALTY_INVALID_OPERATION;
                return;
            }
            (*reply).label = SALTY_OK;
            (*reply).length = 0;
        } else {
            (*reply).label = SALTY_INVALID_OPERATION;
        }
    }
}

/// Check readiness of a single fd for given events. Returns revents bitmask.
unsafe fn check_fd_readiness(cli: *const ClientState, fd: i32, events: u32) -> u32 {
    unsafe {
        if fd < 0 || fd >= (*cli).fds_cap as i32 || (*(*cli).fds.add(fd as usize)).active == 0 {
            return 0x020; // POLLNVAL
        }

        let fde = *(*cli).fds.add(fd as usize);
        let mut rev: u32 = 0;

        match fde.fd_type {
            FD_TYPE_FILE | FD_TYPE_DIR => {
                if events & 0x001 != 0 { rev |= 0x001; }
                if events & 0x004 != 0 { rev |= 0x004; }
            }
            FD_TYPE_DEVICE => {
                if fde.dev_type == DEV_PTY_SLAVE {
                    // Query ttyd for PTY readiness
                    let mut treq = SaltyMsg::zeroed();
                    let mut treply = SaltyMsg::zeroed();
                    treq.label = TTYD_PTY_POLL;
                    treq.regs[0] = fde.sock_id as u64; // pty_id
                    treq.regs[1] = events as u64;
                    treq.length = 2;
                    let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
                    if err == 0 && treply.label == SALTY_OK {
                        rev = treply.regs[0] as u32;
                    }
                } else {
                    if events & 0x004 != 0 { rev |= 0x004; }
                    if events & 0x001 != 0 { rev |= 0x001; }
                }
            }
            FD_TYPE_SOCKET => {
                let sock = find_socket(fde.sock_id);
                if !sock.is_null() && (*sock).state == SOCK_CONNECTED {
                    if events & 0x001 != 0 {
                        if sock_buf_len(sock) > 0 || (*sock).peer_closed != 0 {
                            rev |= 0x001;
                        }
                    }
                    if events & 0x004 != 0 {
                        let peer = find_socket((*sock).peer_sock_id);
                        if !peer.is_null() && sock_buf_free(peer) > 0 {
                            rev |= 0x004;
                        }
                    }
                    if (*sock).peer_closed != 0 {
                        rev |= 0x010;
                    }
                } else if !sock.is_null() && (*sock).state == SOCK_LISTENING {
                    if events & 0x001 != 0 && (*sock).pending_count > 0 {
                        rev |= 0x001;
                    }
                }
            }
            FD_TYPE_PIPE => {
                let pipe = find_pipe(fde.pipe_id());
                if !pipe.is_null() {
                    let is_read = (fde.flags & O_ACCMODE) == 0;
                    if is_read {
                        if events & 0x001 != 0 && pipe_buf_len(pipe) > 0 {
                            rev |= 0x001;
                        }
                        if (*pipe).write_refcount == 0 {
                            rev |= 0x010;
                        }
                    } else {
                        if events & 0x004 != 0 && pipe_buf_free(pipe) > 0 {
                            rev |= 0x004;
                        }
                        if (*pipe).read_refcount == 0 {
                            rev |= 0x008;
                        }
                    }
                }
            }
            _ => {
                return 0x020; // POLLNVAL
            }
        }

        rev
    }
}

unsafe fn handle_epoll_create(reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Find free epoll instance
        let mut epoll_idx: i32 = -1;
        for i in 0..max_epoll_instances() {
            if EPOLLS!()[i].active == 0 {
                epoll_idx = i as i32;
                break;
            }
        }
        if epoll_idx < 0 {
            // No free slot: grow the pool and retry
            if vfs_grow_pool(
                &raw mut EPOLLS_PTR as *mut *mut u8,
                &raw mut EPOLLS_CAP,
                core::mem::size_of::<EpollInstance>(),
            ) != 0 {
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }
            // Retry scan from old_cap
            for i in 0..max_epoll_instances() {
                if EPOLLS!()[i].active == 0 {
                    epoll_idx = i as i32;
                    break;
                }
            }
            if epoll_idx < 0 {
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        // Find free fd
        let mut fd: i32 = -1;
        for i in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(i)).active == 0 {
                fd = i as i32;
                break;
            }
        }
        if fd < 0 {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // Init epoll instance
        EPOLLS!()[epoll_idx as usize].active = 1;
        EPOLLS!()[epoll_idx as usize].owner_badge = badge;
        // Allocate entries array if not yet allocated
        if EPOLLS!()[epoll_idx as usize].entries.is_null() {
            let ptr = vfs_alloc_array::<EpollEntry>(INITIAL_EPOLL_ENTRIES);
            if ptr.is_null() {
                EPOLLS!()[epoll_idx as usize].active = 0;
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }
            EPOLLS!()[epoll_idx as usize].entries = ptr;
            EPOLLS!()[epoll_idx as usize].entries_cap = INITIAL_EPOLL_ENTRIES as u16;
        }
        for j in 0..EPOLLS!()[epoll_idx as usize].entries_cap as usize {
            (*EPOLLS!()[epoll_idx as usize].entries.add(j)).active = 0;
        }

        // Init fd entry
        (*(*cli).fds.add(fd as usize)).active = 1;
        (*(*cli).fds.add(fd as usize)).fd_type = FD_TYPE_EPOLL;
        (*(*cli).fds.add(fd as usize)).sock_id = epoll_idx as u32; // reuse sock_id for epoll index
        (*(*cli).fds.add(fd as usize)).inode = 0;
        (*(*cli).fds.add(fd as usize)).offset = 0;
        (*(*cli).fds.add(fd as usize)).flags = 0;

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = fd as u64;
    }
}

unsafe fn handle_epoll_ctl(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let epfd = (*msg).regs[0] as i32;
        let op = (*msg).regs[1] as i32;
        let fd = (*msg).regs[2] as i32;
        let events = (*msg).regs[3] as u32;
        let data = (*msg).regs[4];

        let cli = get_client(badge);
        if cli.is_null() || epfd < 0 || epfd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(epfd as usize)).active == 0
            || (*(*cli).fds.add(epfd as usize)).fd_type != FD_TYPE_EPOLL
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let ep_idx = (*(*cli).fds.add(epfd as usize)).sock_id as usize;
        if ep_idx >= max_epoll_instances() || EPOLLS!()[ep_idx].active == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Validate target fd
        if fd < 0 || fd >= (*cli).fds_cap as i32 || (*(*cli).fds.add(fd as usize)).active == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let ep = &mut EPOLLS!()[ep_idx];

        match op {
            1 => { // EPOLL_CTL_ADD
                // Check not already present
                for i in 0..(*ep).entries_cap as usize {
                    if (*ep.entries.add(i)).active != 0 && (*ep.entries.add(i)).fd == fd {
                        (*reply).label = SALTY_INVALID_ARGUMENT; // EEXIST
                        return;
                    }
                }
                // Find free slot
                let mut slot: i32 = -1;
                for i in 0..(*ep).entries_cap as usize {
                    if (*ep.entries.add(i)).active == 0 {
                        slot = i as i32;
                        break;
                    }
                }
                if slot < 0 {
                    (*reply).label = SALTY_OUT_OF_MEMORY;
                    return;
                }
                (*ep.entries.add(slot as usize)).active = 1;
                (*ep.entries.add(slot as usize)).fd = fd;
                (*ep.entries.add(slot as usize)).events = events;
                (*ep.entries.add(slot as usize)).data = data;
            }
            2 => { // EPOLL_CTL_DEL
                let mut found = false;
                for i in 0..(*ep).entries_cap as usize {
                    if (*ep.entries.add(i)).active != 0 && (*ep.entries.add(i)).fd == fd {
                        (*ep.entries.add(i)).active = 0;
                        found = true;
                        break;
                    }
                }
                if !found {
                    (*reply).label = SALTY_NOT_FOUND;
                    return;
                }
            }
            3 => { // EPOLL_CTL_MOD
                let mut found = false;
                for i in 0..(*ep).entries_cap as usize {
                    if (*ep.entries.add(i)).active != 0 && (*ep.entries.add(i)).fd == fd {
                        (*ep.entries.add(i)).events = events;
                        (*ep.entries.add(i)).data = data;
                        found = true;
                        break;
                    }
                }
                if !found {
                    (*reply).label = SALTY_NOT_FOUND;
                    return;
                }
            }
            _ => {
                (*reply).label = SALTY_INVALID_ARGUMENT;
                return;
            }
        }

        (*reply).label = SALTY_OK;
        (*reply).length = 0;
    }
}

unsafe fn handle_epoll_wait(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) -> bool {
    unsafe {
        let epfd = (*msg).regs[0] as i32;
        let max_events = (*msg).regs[1] as usize;
        let timeout = (*msg).regs[2] as i32;

        let cli = get_client(badge);
        if cli.is_null() || epfd < 0 || epfd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(epfd as usize)).active == 0
            || (*(*cli).fds.add(epfd as usize)).fd_type != FD_TYPE_EPOLL
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let ep_idx = (*(*cli).fds.add(epfd as usize)).sock_id as usize;
        if ep_idx >= max_epoll_instances() || EPOLLS!()[ep_idx].active == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let ep = &EPOLLS!()[ep_idx];
        let cap = if max_events > 8 { 8 } else { max_events };
        let mut ready_count: usize = 0;

        // Check readiness for each entry in the interest list
        for i in 0..(*ep).entries_cap as usize {
            if (*ep.entries.add(i)).active == 0 {
                continue;
            }
            if ready_count >= cap {
                break;
            }

            let rev = check_fd_readiness(cli, (*ep.entries.add(i)).fd, (*ep.entries.add(i)).events);
            if rev != 0 {
                // Pack: regs[1 + ready*2] = events, regs[2 + ready*2] = data
                (*reply).regs[1 + ready_count * 2] = rev as u64;
                (*reply).regs[2 + ready_count * 2] = (*ep.entries.add(i)).data;
                ready_count += 1;
            }
        }

        if ready_count > 0 || timeout == 0 {
            (*reply).label = SALTY_OK;
            (*reply).regs[0] = ready_count as u64;
            (*reply).length = 1 + (ready_count as u64 * 2);
            return false;
        }

        // Blocking: use poll waiter infrastructure
        let slot = alloc_reply_slot();
        let err = salty::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if err != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        // Build a synthetic poll waiter from epoll entries
        let mut found = false;
        for w in 0..max_poll_waiters() {
            if POLL_WAITERS!()[w].active == 0 {
                POLL_WAITERS!()[w].active = 1;
                POLL_WAITERS!()[w].badge = badge;
                POLL_WAITERS!()[w].reply_slot = slot;
                let mut n: u8 = 0;
                for i in 0..(*ep).entries_cap as usize {
                    if (*ep.entries.add(i)).active == 0 || n >= 8 {
                        continue;
                    }
                    POLL_WAITERS!()[w].fds[n as usize].0 = (*ep.entries.add(i)).fd;
                    POLL_WAITERS!()[w].fds[n as usize].1 = (*ep.entries.add(i)).events as u16;
                    n += 1;
                }
                POLL_WAITERS!()[w].nfds = n;
                found = true;
                break;
            }
        }

        if !found {
            let mut err_reply = SaltyMsg::zeroed();
            err_reply.label = SALTY_OUT_OF_MEMORY;
            ipc::send_ctx(ipc_ctx(), slot, &raw const err_reply);
        }

        true // deferred
    }
}

unsafe fn handle_ioctl(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let request = (*msg).regs[1];
        let arg = (*msg).regs[2];

        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let fde = *(*cli).fds.add(fd as usize);

        if fde.fd_type == FD_TYPE_DEVICE && fde.dev_type == DEV_FB0 {
            handle_ioctl_fb0(request, reply);
            return;
        }

        // Terminal ioctls — supported by both console and PTY devices
        if fde.fd_type != FD_TYPE_DEVICE
            || (fde.dev_type != DEV_CONSOLE && fde.dev_type != DEV_PTY_SLAVE)
        {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let pty_id = if fde.dev_type == DEV_PTY_SLAVE { fde.sock_id as u64 } else { 0u64 };

        match request {
            // TIOCGPGRP: get foreground process group
            0x540F => {
                let mut treq = SaltyMsg::zeroed();
                let mut treply = SaltyMsg::zeroed();
                treq.label = TTYD_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = 0x540F; // TIOCGPGRP
                treq.regs[2] = 0;
                treq.regs[3] = badge;
                treq.length = 4;
                let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
                if err != 0 || treply.label != SALTY_OK {
                    (*reply).label = SALTY_INVALID_OPERATION;
                    return;
                }
                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = treply.regs[0];
            }
            // TIOCSPGRP: set foreground process group
            0x5410 => {
                let mut treq = SaltyMsg::zeroed();
                let mut treply = SaltyMsg::zeroed();
                treq.label = TTYD_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = 0x5410; // TIOCSPGRP
                treq.regs[2] = (*msg).regs[2]; // pgid
                treq.regs[3] = badge;
                treq.length = 4;
                let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
                (*reply).label = if err == 0 { treply.label } else { SALTY_INVALID_OPERATION };
                (*reply).length = 0;
            }
            // TIOCSCTTY: acquire controlling tty
            0x540E => {
                let mut treq = SaltyMsg::zeroed();
                let mut treply = SaltyMsg::zeroed();
                treq.label = TTYD_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = 0x540E; // TIOCSCTTY
                treq.regs[2] = 0;
                treq.regs[3] = badge;
                treq.length = 4;
                let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
                (*reply).label = if err == 0 { treply.label } else { SALTY_INVALID_OPERATION };
                (*reply).length = 0;
            }
            // TIOCNOTTY: release controlling tty
            0x5422 => {
                let mut treq = SaltyMsg::zeroed();
                let mut treply = SaltyMsg::zeroed();
                treq.label = TTYD_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = 0x5422; // TIOCNOTTY
                treq.regs[2] = 0;
                treq.regs[3] = badge;
                treq.length = 4;
                let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
                (*reply).label = if err == 0 { treply.label } else { SALTY_INVALID_OPERATION };
                (*reply).length = 0;
            }
            // TIOCGWINSZ: get terminal window size
            0x5413 => {
                let mut treq = SaltyMsg::zeroed();
                let mut treply = SaltyMsg::zeroed();
                treq.label = TTYD_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = 0x5413; // TIOCGWINSZ
                treq.regs[2] = 0;
                treq.regs[3] = badge;
                treq.length = 4;
                let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_TTYD_EP, &raw const treq, &raw mut treply);
                if err != 0 || treply.label != SALTY_OK {
                    // Fallback to default 80x24
                    (*reply).label = SALTY_OK;
                    (*reply).length = 2;
                    (*reply).regs[0] = (24u64 << 16) | 80u64;
                    (*reply).regs[1] = 0;
                    return;
                }
                (*reply).label = SALTY_OK;
                (*reply).length = 2;
                (*reply).regs[0] = treply.regs[0];
                (*reply).regs[1] = treply.regs[1];
            }
            _ => {
                (*reply).label = SALTY_INVALID_ARGUMENT;
            }
        }
    }
}

unsafe fn handle_ioctl_fb0(request: u64, reply: *mut SaltyMsg) {
    unsafe {
        match request {
            // FBIOGET_VSCREENINFO
            0x4600 => {
                (*reply).label = SALTY_OK;
                (*reply).length = 5;
                (*reply).regs[0] = FB_WIDTH as u64;
                (*reply).regs[1] = FB_HEIGHT as u64;
                (*reply).regs[2] = FB_BPP as u64;
                (*reply).regs[3] = ((FB_RED_POS as u64) << 24)
                    | ((FB_RED_SIZE as u64) << 16)
                    | ((FB_GREEN_POS as u64) << 8)
                    | (FB_GREEN_SIZE as u64);
                (*reply).regs[4] = ((FB_BLUE_POS as u64) << 24)
                    | ((FB_BLUE_SIZE as u64) << 16);
            }
            // FBIOGET_FSCREENINFO
            0x4602 => {
                (*reply).label = SALTY_OK;
                (*reply).length = 3;
                (*reply).regs[0] = FB_PITCH as u64;
                (*reply).regs[1] = FB_HEIGHT as u64 * FB_PITCH as u64;
                (*reply).regs[2] = 0; // type = packed pixels
            }
            _ => {
                (*reply).label = SALTY_INVALID_ARGUMENT;
            }
        }
    }
}

unsafe fn handle_mmap(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let _offset = (*msg).regs[1];
        let length = (*msg).regs[2];

        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let fde = *(*cli).fds.add(fd as usize);

        // SHM mmap — delegate to mmsrv
        if fde.fd_type == FD_TYPE_SHM {
            let inode = inode_by_ino(fde.inode);
            if inode.is_null() || (*inode).ftype != FTYPE_SHM {
                (*reply).label = SALTY_INVALID_OPERATION;
                return;
            }

            let shm_idx = (*inode).dev_type as usize;
            if shm_idx >= max_shm_objects() {
                (*reply).label = SALTY_INVALID_OPERATION;
                return;
            }

            let prot = (*msg).regs[3];

            let mut mm_msg = SaltyMsg::zeroed();
            let mut mm_reply = SaltyMsg::zeroed();
            mm_msg.label = MM_SHM_MAP;
            mm_msg.length = 4;
            mm_msg.regs[0] = shm_idx as u64;
            mm_msg.regs[1] = badge;          // client badge = pid
            mm_msg.regs[2] = 0;              // vaddr = 0 (let mmsrv pick)
            mm_msg.regs[3] = prot;
            let err = ipc::call_ctx(
                ipc_ctx(),
                VFS_CAP_MMSRV_EP,
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            if err != 0 || mm_reply.label != SALTY_OK {
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return;
            }

            // Store the mapped vaddr in fd.offset for MM_SHM_UNMAP on close
            (*(*cli).fds.add(fd as usize)).offset = mm_reply.regs[0];

            (*reply).label = SALTY_OK;
            (*reply).length = 3;
            (*reply).regs[0] = mm_reply.regs[0]; // mapped base addr
            (*reply).regs[1] = 0;
            (*reply).regs[2] = 1;                // server-side mapped flag
            return;
        }

        // FB0 device mmap — cap transfer
        if fde.fd_type != FD_TYPE_DEVICE || fde.dev_type != DEV_FB0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        if FB_MMAP_BADGE != 0 && FB_MMAP_BADGE != badge {
            (*reply).label = SALTY_BUSY;
            return;
        }

        let smem_len = FB_HEIGHT as u64 * FB_PITCH as u64;
        if length > smem_len {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        ipc::set_send_cap_ctx(ipc_ctx(), 0, VFS_CAP_FB_UNTYPED);

        FB_MMAP_BADGE = badge;

        (*reply).label = SALTY_OK;
        (*reply).length = 3;
        (*reply).regs[0] = smem_len;
        (*reply).regs[1] = FB_PITCH as u64;
        (*reply).regs[2] = 0;
    }
}

unsafe fn handle_fcntl(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cmd = (*msg).regs[1] as i32;
        let arg = (*msg).regs[2] as i64;

        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        match cmd {
            // F_DUPFD: duplicate fd, new fd >= arg
            0 | 1030 => {
                // F_DUPFD (0) and F_DUPFD_CLOEXEC (1030)
                let min_fd = if arg < 0 { 0 } else { arg as usize };
                let mut newfd: i32 = -1;
                let mut i = min_fd;
                while i < (*cli).fds_cap as usize {
                    if (*(*cli).fds.add(i)).active == 0 {
                        newfd = i as i32;
                        break;
                    }
                    i += 1;
                }
                if newfd < 0 {
                    (*reply).label = SALTY_OUT_OF_MEMORY;
                    return;
                }

                dup_fd_entry(cli, fd, newfd);
                // F_DUPFD_CLOEXEC sets FD_CLOEXEC on new fd
                if cmd == 1030 {
                    *(*cli).fd_flags.add(newfd as usize) = 1; // FD_CLOEXEC
                } else {
                    *(*cli).fd_flags.add(newfd as usize) = 0;
                }

                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = newfd as u64;
            }
            // F_GETFD: get fd flags
            1 => {
                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = *(*cli).fd_flags.add(fd as usize) as u64;
            }
            // F_SETFD: set fd flags
            2 => {
                *(*cli).fd_flags.add(fd as usize) = arg as u8;
                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
            }
            // F_GETFL: get file status flags
            3 => {
                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = (*(*cli).fds.add(fd as usize)).flags as u64;
            }
            // F_SETFL: set file status flags (only O_APPEND, O_NONBLOCK are changeable)
            4 => {
                let changeable = O_APPEND | 0x0800; // O_APPEND | O_NONBLOCK
                let preserved = (*(*cli).fds.add(fd as usize)).flags & !changeable;
                (*(*cli).fds.add(fd as usize)).flags = preserved | (arg as u32 & changeable);
                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
            }
            _ => {
                (*reply).label = SALTY_INVALID_ARGUMENT;
            }
        }
    }
}

unsafe fn handle_chdir(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) = normalize_path_for_client(
            badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };

        // Validate that path exists and is a directory
        let inode = resolve_path(path_ptr, path_len);
        if inode.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }
        if (*inode).ftype != FTYPE_DIRECTORY && (*inode).ftype != FTYPE_MOUNT_POINT {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // Store the new cwd
        let copy_len = if (path_len as usize) < 127 { path_len as usize } else { 127 };
        let mut i = 0;
        while i < copy_len {
            (*cli).cwd[i] = *path_ptr.add(i);
            i += 1;
        }
        // Ensure null-terminated
        (*cli).cwd[copy_len] = 0;
        // Zero rest
        i = copy_len + 1;
        while i < 128 {
            (*cli).cwd[i] = 0;
            i += 1;
        }

        (*reply).label = SALTY_OK;
    }
}

unsafe fn handle_getcwd(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let max_size = (*msg).regs[0] as usize;

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // Measure cwd length
        let mut cwd_len: usize = 0;
        while cwd_len < 128 && (*cli).cwd[cwd_len] != 0 {
            cwd_len += 1;
        }
        if cwd_len == 0 {
            // Default to "/"
            cwd_len = 1;
            (*cli).cwd[0] = b'/';
            (*cli).cwd[1] = 0;
        }

        // POSIX getcwd(): caller buffer must fit full path + trailing NUL.
        if max_size == 0 || cwd_len + 1 > max_size {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Pack cwd bytes into reply regs[1..]
        let copy_len = cwd_len;
        (*reply).label = SALTY_OK;
        (*reply).regs[0] = copy_len as u64;
        let dst = &mut (*reply).regs[1] as *mut u64 as *mut u8;
        let mut i = 0;
        while i < copy_len {
            *dst.add(i) = (*cli).cwd[i];
            i += 1;
        }
        (*reply).length = 1 + ((copy_len as u64 + 7) / 8);
    }
}

// ======================================================================
// Socket request handlers
// ======================================================================

unsafe fn handle_socket(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) -> bool {
    unsafe {
        let _domain = (*msg).regs[0] as i32; // AF_UNIX only
        let _sock_type = (*msg).regs[1] as i32; // SOCK_STREAM only

        let sock = alloc_socket();
        if sock.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return false;
        }

        let cli = get_client(badge);
        if cli.is_null() {
            (*sock).active = 0;
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return false;
        }

        for fd in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(fd)).active == 0 {
                (*(*cli).fds.add(fd)).active = 1;
                (*(*cli).fds.add(fd)).fd_type = FD_TYPE_SOCKET;
                (*(*cli).fds.add(fd)).sock_id = (*sock).sock_id;
                (*(*cli).fds.add(fd)).offset = 0;
                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = fd as u64;
                return false;
            }
        }

        (*sock).active = 0;
        (*reply).label = SALTY_OUT_OF_MEMORY;
        false
    }
}

unsafe fn handle_bind(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let sock = find_socket((*(*cli).fds.add(fd as usize)).sock_id);
        if sock.is_null() || (*sock).state != SOCK_UNBOUND {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        // Extract path
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 1, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }
        let Some((path_ptr, path_len)) = normalize_path_for_client(
            badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        };

        // Create a socket inode at this path
        let existing = resolve_path(path_ptr, path_len);
        if !existing.is_null() {
            (*reply).label = SALTY_ALREADY_EXISTS;
            return false;
        }

        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent(path_ptr, path_len, &mut child_name, &mut child_len);
        if parent.is_null() || (*parent).ftype != FTYPE_DIRECTORY || (*parent).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        let inode = alloc_inode();
        if inode.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return false;
        }

        (*inode).ftype = FTYPE_SOCKET;
        (*inode).mode = S_IFSOCK_L | 0o777;
        (*inode).parent_ino = (*parent).ino;
        dir_add_entry(parent, child_name, child_len, (*inode).ino);

        (*sock).bound_ino = (*inode).ino;
        (*sock).state = SOCK_BOUND;

        (*reply).label = SALTY_OK;
        false
    }
}

unsafe fn handle_listen(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let backlog = (*msg).regs[1] as u8;

        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let sock = find_socket((*(*cli).fds.add(fd as usize)).sock_id);
        if sock.is_null() || (*sock).state != SOCK_BOUND {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        (*sock).state = SOCK_LISTENING;
        (*sock).backlog = if backlog > (*sock).pending_cap { (*sock).pending_cap } else { backlog };
        (*reply).label = SALTY_OK;
        false
    }
}

unsafe fn handle_accept(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let listen_sock = find_socket((*(*cli).fds.add(fd as usize)).sock_id);
        if listen_sock.is_null() || (*listen_sock).state != SOCK_LISTENING {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        // Check for pending connection
        for i in 0..(*listen_sock).pending_cap as usize {
            if (*(*listen_sock).pending.add(i)).active != 0 {
                let pend = *(*listen_sock).pending.add(i);
                (*(*listen_sock).pending.add(i)).active = 0;
                (*listen_sock).pending_count -= 1;

                // Create server-side socket
                let srv_sock = alloc_socket();
                if srv_sock.is_null() {
                    // Wake blocked connect caller with error
                    if pend.reply_slot != 0 {
                        let mut err_reply = SaltyMsg::zeroed();
                        err_reply.label = SALTY_OUT_OF_MEMORY;
                        ipc::send_ctx(ipc_ctx(), pend.reply_slot, &raw const err_reply);
                    }
                    (*reply).label = SALTY_OUT_OF_MEMORY;
                    return false;
                }
                (*srv_sock).state = SOCK_CONNECTED;

                // Find the connecting socket
                let cli_sock = find_socket(pend.sock_id);
                if cli_sock.is_null() {
                    (*srv_sock).active = 0;
                    // Wake blocked connect caller with error
                    if pend.reply_slot != 0 {
                        let mut err_reply = SaltyMsg::zeroed();
                        err_reply.label = SALTY_INVALID_OPERATION;
                        ipc::send_ctx(ipc_ctx(), pend.reply_slot, &raw const err_reply);
                    }
                    (*reply).label = SALTY_INVALID_OPERATION;
                    return false;
                }

                // Link peers
                (*srv_sock).peer_sock_id = (*cli_sock).sock_id;
                (*srv_sock).peer_badge = pend.client_badge;
                (*cli_sock).peer_sock_id = (*srv_sock).sock_id;
                (*cli_sock).peer_badge = badge;
                (*cli_sock).state = SOCK_CONNECTED;

                // Allocate fd for accepted socket
                let mut new_fd: i32 = -1;
                for fdn in 0..(*cli).fds_cap as usize {
                    if (*(*cli).fds.add(fdn)).active == 0 {
                        (*(*cli).fds.add(fdn)).active = 1;
                        (*(*cli).fds.add(fdn)).fd_type = FD_TYPE_SOCKET;
                        (*(*cli).fds.add(fdn)).sock_id = (*srv_sock).sock_id;
                        new_fd = fdn as i32;
                        break;
                    }
                }

                if new_fd < 0 {
                    (*srv_sock).active = 0;
                    // Wake blocked connect caller with error
                    if pend.reply_slot != 0 {
                        let mut err_reply = SaltyMsg::zeroed();
                        err_reply.label = SALTY_OUT_OF_MEMORY;
                        ipc::send_ctx(ipc_ctx(), pend.reply_slot, &raw const err_reply);
                    }
                    (*reply).label = SALTY_OUT_OF_MEMORY;
                    return false;
                }

                // Wake the blocked connect() caller
                if pend.reply_slot != 0 {
                    let mut wake_reply = SaltyMsg::zeroed();
                    wake_reply.label = SALTY_OK;
                    ipc::send_ctx(ipc_ctx(), pend.reply_slot, &raw const wake_reply);
                }

                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = new_fd as u64;
                return false;
            }
        }

        // No pending connections — block accepter
        let slot = alloc_reply_slot();
        let err = salty::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if err != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }
        (*listen_sock).accept_reply_slot = slot;
        (*listen_sock).accept_badge = badge;
        true // deferred reply
    }
}

unsafe fn handle_connect(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let cli_sock = find_socket((*(*cli).fds.add(fd as usize)).sock_id);
        if cli_sock.is_null() || (*cli_sock).state != SOCK_UNBOUND {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        // Resolve path to find listening socket
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 1, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }
        let Some((path_ptr, path_len)) = normalize_path_for_client(
            badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        };
        let inode = resolve_path(path_ptr, path_len);
        if inode.is_null() || (*inode).ftype != FTYPE_SOCKET {
            (*reply).label = SALTY_NOT_FOUND;
            return false;
        }

        // Find the listener
        let mut listen_sock: *mut SocketState = core::ptr::null_mut();
        for i in 0..max_sockets() {
            if SOCKETS!()[i].active != 0
                && SOCKETS!()[i].state == SOCK_LISTENING
                && SOCKETS!()[i].bound_ino == (*inode).ino
            {
                listen_sock = &raw mut SOCKETS!()[i];
                break;
            }
        }

        if listen_sock.is_null() {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        // If accepter is waiting, connect immediately
        if (*listen_sock).accept_reply_slot != 0 {
            let srv_sock = alloc_socket();
            if srv_sock.is_null() {
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return false;
            }
            (*srv_sock).state = SOCK_CONNECTED;
            (*cli_sock).state = SOCK_CONNECTED;

            (*srv_sock).peer_sock_id = (*cli_sock).sock_id;
            (*srv_sock).peer_badge = badge;
            (*cli_sock).peer_sock_id = (*srv_sock).sock_id;
            (*cli_sock).peer_badge = (*listen_sock).accept_badge;

            // Allocate fd for accepted socket on accepter's side
            let accepter_cli = get_client((*listen_sock).accept_badge);
            let mut new_fd: i32 = -1;
            if !accepter_cli.is_null() {
                for fdn in 0..(*cli).fds_cap as usize {
                    if (*(*accepter_cli).fds.add(fdn)).active == 0 {
                        (*(*accepter_cli).fds.add(fdn)).active = 1;
                        (*(*accepter_cli).fds.add(fdn)).fd_type = FD_TYPE_SOCKET;
                        (*(*accepter_cli).fds.add(fdn)).sock_id = (*srv_sock).sock_id;
                        new_fd = fdn as i32;
                        break;
                    }
                }
            }

            // Wake blocked accept() caller
            let mut wake_reply = SaltyMsg::zeroed();
            wake_reply.label = SALTY_OK;
            wake_reply.length = 1;
            wake_reply.regs[0] = if new_fd >= 0 { new_fd as u64 } else { u64::MAX };
            ipc::send_ctx(ipc_ctx(), (*listen_sock).accept_reply_slot, &raw const wake_reply);
            (*listen_sock).accept_reply_slot = 0;
            (*listen_sock).accept_badge = 0;

            (*reply).label = SALTY_OK;
            return false;
        }

        // No accepter waiting — queue as pending and block
        if (*listen_sock).pending_count >= (*listen_sock).backlog {
            (*reply).label = SALTY_BUSY;
            return false;
        }

        let slot = alloc_reply_slot();
        let err = salty::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if err != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        (*cli_sock).state = SOCK_CONNECTING;

        for i in 0..(*listen_sock).pending_cap as usize {
            if (*(*listen_sock).pending.add(i)).active == 0 {
                (*(*listen_sock).pending.add(i)).active = 1;
                (*(*listen_sock).pending.add(i)).client_badge = badge;
                (*(*listen_sock).pending.add(i)).sock_id = (*cli_sock).sock_id;
                (*(*listen_sock).pending.add(i)).reply_slot = slot;
                (*listen_sock).pending_count += 1;
                break;
            }
        }

        true // deferred reply
    }
}

unsafe fn handle_shutdown(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let how = (*msg).regs[1] as i32;

        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let sock = find_socket((*(*cli).fds.add(fd as usize)).sock_id);
        if sock.is_null() {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        if how == 0 || how == 2 { (*sock).shut_rd = 1; }
        if how == 1 || how == 2 {
            (*sock).shut_wr = 1;
            // Signal peer
            if (*sock).peer_sock_id != 0 {
                let peer = find_socket((*sock).peer_sock_id);
                if !peer.is_null() {
                    (*peer).peer_closed = 1;
                    // Wake blocked reader on peer
                    if (*peer).recv_reply_slot != 0 {
                        let mut wake = SaltyMsg::zeroed();
                        wake.label = SALTY_OK;
                        wake.length = 1;
                        wake.regs[0] = 0; // EOF
                        ipc::send_ctx(ipc_ctx(), (*peer).recv_reply_slot, &raw const wake);
                        (*peer).recv_reply_slot = 0;
                    }
                    wake_poll_waiters((*peer).peer_badge, -1, 0x010); // POLLHUP
                }
            }
        }

        (*reply).label = SALTY_OK;
        false
    }
}

unsafe fn handle_sockpair(_msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) -> bool {
    unsafe {
        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return false;
        }

        let s1 = alloc_socket();
        let s2 = alloc_socket();
        if s1.is_null() || s2.is_null() {
            if !s1.is_null() { (*s1).active = 0; }
            if !s2.is_null() { (*s2).active = 0; }
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return false;
        }

        (*s1).state = SOCK_CONNECTED;
        (*s2).state = SOCK_CONNECTED;
        (*s1).peer_sock_id = (*s2).sock_id;
        (*s1).peer_badge = badge;
        (*s2).peer_sock_id = (*s1).sock_id;
        (*s2).peer_badge = badge;

        let mut fd1: i32 = -1;
        let mut fd2: i32 = -1;
        for fdn in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(fdn)).active == 0 {
                if fd1 < 0 {
                    (*(*cli).fds.add(fdn)).active = 1;
                    (*(*cli).fds.add(fdn)).fd_type = FD_TYPE_SOCKET;
                    (*(*cli).fds.add(fdn)).sock_id = (*s1).sock_id;
                    fd1 = fdn as i32;
                } else if fd2 < 0 {
                    (*(*cli).fds.add(fdn)).active = 1;
                    (*(*cli).fds.add(fdn)).fd_type = FD_TYPE_SOCKET;
                    (*(*cli).fds.add(fdn)).sock_id = (*s2).sock_id;
                    fd2 = fdn as i32;
                    break;
                }
            }
        }

        if fd1 < 0 || fd2 < 0 {
            (*s1).active = 0;
            (*s2).active = 0;
            if fd1 >= 0 { (*(*cli).fds.add(fd1 as usize)).active = 0; }
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return false;
        }

        (*reply).label = SALTY_OK;
        (*reply).length = 2;
        (*reply).regs[0] = fd1 as u64;
        (*reply).regs[1] = fd2 as u64;
        false
    }
}

/// Handle read on a socket fd
unsafe fn handle_socket_read(fde: *mut FdEntry, reply: *mut SaltyMsg, badge: u64) -> bool {
    unsafe {
        let sock = find_socket((*fde).sock_id);
        if sock.is_null() || (*sock).state != SOCK_CONNECTED {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        if (*sock).shut_rd != 0 {
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return false;
        }

        let avail = sock_buf_len(sock);
        if avail > 0 {
            let mut count = avail;
            if count > 152 { count = 152; }
            let dst = &raw mut (*reply).regs[1] as *mut u8;
            let actual = sock_buf_read(sock, dst, count);
            (*reply).label = SALTY_OK;
            (*reply).length = 1 + ((actual as u64 + 7) / 8);
            (*reply).regs[0] = actual as u64;

            // Wake peer's blocked writer poll watchers
            if (*sock).peer_sock_id != 0 {
                wake_poll_waiters((*sock).peer_badge, -1, 0x004); // POLLOUT
            }
            return false;
        }

        if (*sock).peer_closed != 0 {
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0; // EOF
            return false;
        }

        // Block reader — save caller
        let slot = alloc_reply_slot();
        let err = salty::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if err != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }
        (*sock).recv_reply_slot = slot;
        (*sock).recv_badge = badge;
        true // deferred
    }
}

/// Handle write on a socket fd
unsafe fn handle_socket_write(msg: *const SaltyMsg, fde: *mut FdEntry, reply: *mut SaltyMsg) -> bool {
    unsafe {
        let sock = find_socket((*fde).sock_id);
        if sock.is_null() || (*sock).state != SOCK_CONNECTED || (*sock).shut_wr != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        let peer = find_socket((*sock).peer_sock_id);
        if peer.is_null() || (*peer).peer_closed != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        let count = (*msg).regs[1];
        let src = &(*msg).regs[2] as *const u64 as *const u8;
        let mut actual_count = count;
        if actual_count > 144 { actual_count = 144; }

        let written = sock_buf_write(peer, src, actual_count as u16);

        // Wake blocked reader on peer
        if written > 0 && (*peer).recv_reply_slot != 0 {
            let mut wake = SaltyMsg::zeroed();
            let avail = sock_buf_len(peer);
            let mut rcount = avail;
            if rcount > 152 { rcount = 152; }
            let dst = &raw mut wake.regs[1] as *mut u8;
            let actual = sock_buf_read(peer, dst, rcount);
            wake.label = SALTY_OK;
            wake.length = 1 + ((actual as u64 + 7) / 8);
            wake.regs[0] = actual as u64;
            ipc::send_ctx(ipc_ctx(), (*peer).recv_reply_slot, &raw const wake);
            (*peer).recv_reply_slot = 0;
        }

        // Wake poll waiters watching this peer for POLLIN
        if written > 0 {
            wake_poll_waiters((*peer).peer_badge, -1, 0x001); // POLLIN
        }

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = written as u64;
        false
    }
}

/// Close a socket fd — decrement refcount, only destroy when last reference closed
unsafe fn close_socket(fde: *mut FdEntry) {
    unsafe {
        let sock = find_socket((*fde).sock_id);
        if sock.is_null() { return; }

        // Decrement refcount — only destroy socket when last fd is closed
        (*sock).refcount = (*sock).refcount.saturating_sub(1);
        if (*sock).refcount > 0 { return; }

        // Signal peer
        if (*sock).peer_sock_id != 0 {
            let peer = find_socket((*sock).peer_sock_id);
            if !peer.is_null() {
                (*peer).peer_closed = 1;
                // Wake blocked reader
                if (*peer).recv_reply_slot != 0 {
                    let mut wake = SaltyMsg::zeroed();
                    wake.label = SALTY_OK;
                    wake.length = 1;
                    wake.regs[0] = 0;
                    ipc::send_ctx(ipc_ctx(), (*peer).recv_reply_slot, &raw const wake);
                    (*peer).recv_reply_slot = 0;
                }
            }
        }

        // Wake blocked accept() caller
        if (*sock).accept_reply_slot != 0 {
            let mut wake = SaltyMsg::zeroed();
            wake.label = SALTY_INVALID_OPERATION;
            ipc::send_ctx(ipc_ctx(), (*sock).accept_reply_slot, &raw const wake);
            (*sock).accept_reply_slot = 0;
        }

        // Wake pending connect() callers
        for i in 0..(*sock).pending_cap as usize {
            if (*(*sock).pending.add(i)).active != 0 && (*(*sock).pending.add(i)).reply_slot != 0 {
                let mut wake = SaltyMsg::zeroed();
                wake.label = SALTY_INVALID_OPERATION;
                ipc::send_ctx(ipc_ctx(), (*(*sock).pending.add(i)).reply_slot, &raw const wake);
                (*(*sock).pending.add(i)).active = 0;
            }
        }
        (*sock).pending_count = 0;

        // Remove bound inode
        if (*sock).bound_ino != 0 {
            let inode = inode_by_ino((*sock).bound_ino);
            if !inode.is_null() {
                (*inode).active = 0;
            }
        }

        (*sock).state = SOCK_CLOSED;
        (*sock).active = 0;
    }
}

// ======================================================================
// Sendmsg / Recvmsg (SCM_RIGHTS)
// ======================================================================

unsafe fn handle_sendmsg(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let data_len = (*msg).regs[1];
        let fd_count = (*msg).regs[2] as u32;

        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let sock = find_socket((*(*cli).fds.add(fd as usize)).sock_id);
        if sock.is_null() || (*sock).state != SOCK_CONNECTED || (*sock).shut_wr != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        let peer = find_socket((*sock).peer_sock_id);
        if peer.is_null() {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        // Write data to peer's buffer
        let mut actual_data = data_len;
        if actual_data > 120 { actual_data = 120; }
        let src = &(*msg).regs[3] as *const u64 as *const u8;
        let written = sock_buf_write(peer, src, actual_data as u16);

        // Store SCM_RIGHTS fd numbers for peer to receive.
        // For simplicity we store the fd numbers; recvmsg will
        // duplicate them from sender's client state into receiver's.
        let actual_fds = if fd_count > 4 { 4 } else { fd_count };
        (*peer).pending_cap_count = actual_fds as u8;
        let data_regs = (actual_data + 7) / 8;
        let fd_src = &(*msg).regs[3 + data_regs as usize] as *const u64 as *const i32;
        for i in 0..actual_fds as usize {
            // Store as (badge, fd) pair: badge of sender and fd index
            (*peer).pending_caps[i] = ((badge << 32) | (*fd_src.add(i) as u32 as u64)) & 0xFFFF_FFFF_FFFF_FFFF;
        }

        // Wake blocked reader on peer
        if written > 0 && (*peer).recv_reply_slot != 0 {
            let mut wake = SaltyMsg::zeroed();
            let avail = sock_buf_len(peer);
            let mut rcount = avail;
            if rcount > 120 { rcount = 120; }
            let dst = &raw mut wake.regs[2] as *mut u8;
            let actual = sock_buf_read(peer, dst, rcount);
            wake.label = SALTY_OK;
            wake.regs[0] = actual as u64;
            wake.regs[1] = 0; // no caps in wake path
            wake.length = 2 + ((actual as u64 + 7) / 8);
            ipc::send_ctx(ipc_ctx(), (*peer).recv_reply_slot, &raw const wake);
            (*peer).recv_reply_slot = 0;
        }

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = written as u64;
        false
    }
}

unsafe fn handle_recvmsg(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let max_data = (*msg).regs[1];

        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
            || (*(*cli).fds.add(fd as usize)).fd_type != FD_TYPE_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let sock = find_socket((*(*cli).fds.add(fd as usize)).sock_id);
        if sock.is_null() || (*sock).state != SOCK_CONNECTED {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        let avail = sock_buf_len(sock);
        if avail == 0 && (*sock).pending_cap_count == 0 {
            if (*sock).peer_closed != 0 {
                (*reply).label = SALTY_OK;
                (*reply).length = 2;
                (*reply).regs[0] = 0;
                (*reply).regs[1] = 0;
                return false;
            }

            // Block
            let slot = alloc_reply_slot();
            let err = salty::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
            if err != 0 {
                (*reply).label = SALTY_INVALID_OPERATION;
                return false;
            }
            (*sock).recv_reply_slot = slot;
            (*sock).recv_badge = badge;
            return true;
        }

        // Read data
        let mut count = if avail > 120 { 120 } else { avail };
        if count as u64 > max_data { count = max_data as u16; }
        let dst = &raw mut (*reply).regs[2] as *mut u8;
        let actual = sock_buf_read(sock, dst, count);

        // Handle pending SCM_RIGHTS fds
        let cap_count = (*sock).pending_cap_count;
        let mut new_fd_count: u32 = 0;
        let data_regs = (actual as u64 + 7) / 8;

        if cap_count > 0 {
            let fd_dst = &raw mut (*reply).regs[2 + data_regs as usize] as *mut i32;
            for i in 0..cap_count as usize {
                let packed = (*sock).pending_caps[i];
                let src_badge = packed >> 32;
                let src_fd = (packed & 0xFFFF_FFFF) as i32;

                // Look up source client and fd
                let src_cli = get_client(src_badge);
                if src_cli.is_null() || src_fd < 0 || src_fd >= (*src_cli).fds_cap as i32 { continue; }
                let src_fde = *(*src_cli).fds.add(src_fd as usize);
                if src_fde.active == 0 { continue; }

                // Duplicate fd into receiver's fd table
                let mut new_fd: i32 = -1;
                for fdn in 0..(*cli).fds_cap as usize {
                    if (*(*cli).fds.add(fdn)).active == 0 {
                        *(*cli).fds.add(fdn) = src_fde;
                        new_fd = fdn as i32;
                        break;
                    }
                }

                if new_fd >= 0 {
                    *fd_dst.add(new_fd_count as usize) = new_fd;
                    new_fd_count += 1;
                }
            }
            (*sock).pending_cap_count = 0;
        }

        (*reply).label = SALTY_OK;
        (*reply).regs[0] = actual as u64;
        (*reply).regs[1] = new_fd_count as u64;
        (*reply).length = 2 + data_regs + ((new_fd_count as u64 * 4 + 7) / 8);
        false
    }
}

// ======================================================================
// Poll handler
// ======================================================================

unsafe fn handle_poll(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) -> bool {
    unsafe {
        let nfds = (*msg).regs[0] as u32;
        let timeout = (*msg).regs[1] as i32;
        let actual_nfds = if nfds > 8 { 8 } else { nfds };

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let mut ready_count: i32 = 0;
        let mut revents_arr: [u16; 8] = [0; 8];

        for i in 0..actual_nfds as usize {
            let pfd = (*msg).regs[2 + i * 2] as i32;
            let events = (*msg).regs[2 + i * 2 + 1] as u16;

            if pfd < 0 || pfd >= (*cli).fds_cap as i32 || (*(*cli).fds.add(pfd as usize)).active == 0 {
                revents_arr[i] = 0x020; // POLLNVAL
                ready_count += 1;
                continue;
            }

            let fde = *(*cli).fds.add(pfd as usize);
            let mut rev: u16 = 0;

            match fde.fd_type {
                FD_TYPE_FILE | FD_TYPE_DIR => {
                    // Files/dirs always ready
                    if events & 0x001 != 0 { rev |= 0x001; } // POLLIN
                    if events & 0x004 != 0 { rev |= 0x004; } // POLLOUT
                }
                FD_TYPE_DEVICE => {
                    if events & 0x004 != 0 { rev |= 0x004; } // POLLOUT always
                    if events & 0x001 != 0 { rev |= 0x001; } // POLLIN - assume ready for console
                }
                FD_TYPE_SOCKET => {
                    let sock = find_socket(fde.sock_id);
                    if !sock.is_null() && (*sock).state == SOCK_CONNECTED {
                        if events & 0x001 != 0 { // POLLIN
                            if sock_buf_len(sock) > 0 || (*sock).peer_closed != 0 {
                                rev |= 0x001;
                            }
                        }
                        if events & 0x004 != 0 { // POLLOUT
                            let peer = find_socket((*sock).peer_sock_id);
                            if !peer.is_null() && sock_buf_free(peer) > 0 {
                                rev |= 0x004;
                            }
                        }
                        if (*sock).peer_closed != 0 {
                            rev |= 0x010; // POLLHUP
                        }
                    } else if !sock.is_null() && (*sock).state == SOCK_LISTENING {
                        if events & 0x001 != 0 && (*sock).pending_count > 0 {
                            rev |= 0x001;
                        }
                    }
                }
                FD_TYPE_PIPE => {
                    let pipe = find_pipe(fde.pipe_id());
                    if !pipe.is_null() {
                        let is_read = (fde.flags & O_ACCMODE) == 0;
                        if is_read {
                            // Read end
                            if events & 0x001 != 0 && pipe_buf_len(pipe) > 0 {
                                rev |= 0x001; // POLLIN
                            }
                            if (*pipe).write_refcount == 0 {
                                rev |= 0x010; // POLLHUP — no writers
                            }
                        } else {
                            // Write end
                            if events & 0x004 != 0 && pipe_buf_free(pipe) > 0 {
                                rev |= 0x004; // POLLOUT
                            }
                            if (*pipe).read_refcount == 0 {
                                rev |= 0x008; // POLLERR — no readers
                            }
                        }
                    }
                }
                _ => {
                    revents_arr[i] = 0x020; // POLLNVAL
                    ready_count += 1;
                    continue;
                }
            }

            revents_arr[i] = rev;
            if rev != 0 { ready_count += 1; }
        }

        if ready_count > 0 || timeout == 0 {
            (*reply).label = SALTY_OK;
            (*reply).regs[0] = ready_count as u64;
            for i in 0..actual_nfds as usize {
                (*reply).regs[1 + i] = revents_arr[i] as u64;
            }
            (*reply).length = 1 + actual_nfds as u64;
            return false;
        }

        // Block — register poll waiter
        let slot = alloc_reply_slot();
        let err = salty::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if err != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        let mut found = false;
        for i in 0..max_poll_waiters() {
            if POLL_WAITERS!()[i].active == 0 {
                POLL_WAITERS!()[i].active = 1;
                POLL_WAITERS!()[i].badge = badge;
                POLL_WAITERS!()[i].reply_slot = slot;
                POLL_WAITERS!()[i].nfds = actual_nfds as u8;
                for j in 0..actual_nfds as usize {
                    POLL_WAITERS!()[i].fds[j].0 = (*msg).regs[2 + j * 2] as i32;
                    POLL_WAITERS!()[i].fds[j].1 = (*msg).regs[2 + j * 2 + 1] as u16;
                }
                found = true;
                break;
            }
        }

        if !found {
            // No free waiter slot: grow and retry
            if vfs_grow_pool(
                &raw mut POLL_WAITERS_PTR as *mut *mut u8,
                &raw mut POLL_WAITERS_CAP,
                core::mem::size_of::<PollWaiter>(),
            ) == 0 {
                for i in 0..max_poll_waiters() {
                    if POLL_WAITERS!()[i].active == 0 {
                        POLL_WAITERS!()[i].active = 1;
                        POLL_WAITERS!()[i].badge = badge;
                        POLL_WAITERS!()[i].reply_slot = slot;
                        POLL_WAITERS!()[i].nfds = actual_nfds as u8;
                        for j in 0..actual_nfds as usize {
                            POLL_WAITERS!()[i].fds[j].0 = (*msg).regs[2 + j * 2] as i32;
                            POLL_WAITERS!()[i].fds[j].1 = (*msg).regs[2 + j * 2 + 1] as u16;
                        }
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                // Still no slot — reply with error via saved cap
                let mut err_reply = SaltyMsg::zeroed();
                err_reply.label = SALTY_OUT_OF_MEMORY;
                ipc::send_ctx(ipc_ctx(), slot, &raw const err_reply);
            }
        }

        true // deferred (already replied via saved cap)
    }
}

// ======================================================================
// SHM handlers
// ======================================================================

unsafe fn handle_shm_open(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) -> bool {
    unsafe {
        let flags = (*msg).regs[0] as u32;
        let mut path = [0u8; MAX_PATH_LEN];
        let name_len = extract_path(msg, 1, path.as_mut_ptr());

        // Build full path /dev/shm/<name>
        let mut full_path = [0u8; MAX_PATH_LEN];
        let prefix = b"/dev/shm/";
        for i in 0..prefix.len() { full_path[i] = prefix[i]; }
        for i in 0..name_len as usize {
            if prefix.len() + i >= MAX_PATH_LEN { break; }
            full_path[prefix.len() + i] = path[i];
        }
        let full_len = (prefix.len() + name_len as usize) as u8;

        let existing = resolve_path(full_path.as_ptr(), full_len);

        if !existing.is_null() {
            if (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL) {
                (*reply).label = SALTY_ALREADY_EXISTS;
                return false;
            }
            // Open existing
            let cli = get_client(badge);
            if cli.is_null() {
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return false;
            }
            for fd in 0..(*cli).fds_cap as usize {
                if (*(*cli).fds.add(fd)).active == 0 {
                    (*(*cli).fds.add(fd)).active = 1;
                    (*(*cli).fds.add(fd)).fd_type = FD_TYPE_SHM;
                    (*(*cli).fds.add(fd)).inode = (*existing).ino;
                    inode_open((*existing).ino);
                    (*reply).label = SALTY_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = fd as u64;
                    return false;
                }
            }
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return false;
        }

        if (flags & 0x0040) == 0 { // O_CREAT not set
            (*reply).label = SALTY_NOT_FOUND;
            return false;
        }

        // Ensure /dev/shm exists
        let shm_dir = resolve_path(b"/dev/shm".as_ptr(), 8);
        let parent = if shm_dir.is_null() {
            // Create /dev/shm
            let dev_dir = resolve_path(b"/dev".as_ptr(), 4);
            if dev_dir.is_null() {
                (*reply).label = SALTY_INVALID_OPERATION;
                return false;
            }
            let d = alloc_inode();
            if d.is_null() {
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return false;
            }
            (*d).ftype = FTYPE_DIRECTORY;
            (*d).mode = S_IFDIR_L | 0o755;
            (*d).nlink = 2;
            (*d).parent_ino = (*dev_dir).ino;
            dir_add_entry(dev_dir, b"shm".as_ptr(), 3, (*d).ino);
            d
        } else {
            shm_dir
        };

        // Create SHM inode
        let inode = alloc_inode();
        if inode.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return false;
        }
        (*inode).ftype = FTYPE_SHM;
        (*inode).mode = S_IFREG_L | 0o666;
        (*inode).parent_ino = (*parent).ino;
        (*inode).size = 0;
        dir_add_entry(parent, path.as_ptr(), name_len, (*inode).ino);

        // Allocate SHM data
        let mut shm_idx: i32 = -1;
        for i in 0..max_shm_objects() {
            if SHM_DATA!()[i].active == 0 {
                shm_idx = i as i32;
                SHM_DATA!()[i].active = 1;
                break;
            }
        }
        if shm_idx < 0 {
            // No free slot: grow and retry
            if vfs_grow_pool(
                &raw mut SHM_DATA_PTR as *mut *mut u8,
                &raw mut SHM_CAP,
                core::mem::size_of::<ShmData>(),
            ) == 0 {
                for i in 0..max_shm_objects() {
                    if SHM_DATA!()[i].active == 0 {
                        shm_idx = i as i32;
                        SHM_DATA!()[i].active = 1;
                        break;
                    }
                }
            }
            if shm_idx < 0 {
                (*inode).active = 0;
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return false;
            }
        }

        // Store SHM index in inode dev_type field (repurposed)
        (*inode).dev_type = shm_idx as u8;

        let cli = get_client(badge);
        if cli.is_null() {
            (*inode).active = 0;
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return false;
        }

        for fd in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(fd)).active == 0 {
                (*(*cli).fds.add(fd)).active = 1;
                (*(*cli).fds.add(fd)).fd_type = FD_TYPE_SHM;
                (*(*cli).fds.add(fd)).inode = (*inode).ino;
                inode_open((*inode).ino);
                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = fd as u64;
                return false;
            }
        }

        (*inode).active = 0;
        (*reply).label = SALTY_OUT_OF_MEMORY;
        false
    }
}

unsafe fn handle_shm_unlink(msg: *const SaltyMsg, reply: *mut SaltyMsg) -> bool {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let name_len = extract_path(msg, 0, path.as_mut_ptr());

        let mut full_path = [0u8; MAX_PATH_LEN];
        let prefix = b"/dev/shm/";
        for i in 0..prefix.len() { full_path[i] = prefix[i]; }
        for i in 0..name_len as usize {
            if prefix.len() + i >= MAX_PATH_LEN { break; }
            full_path[prefix.len() + i] = path[i];
        }
        let full_len = (prefix.len() + name_len as usize) as u8;

        let inode = resolve_path(full_path.as_ptr(), full_len);
        if inode.is_null() || (*inode).ftype != FTYPE_SHM {
            (*reply).label = SALTY_NOT_FOUND;
            return false;
        }

        // Remove from parent
        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent(full_path.as_ptr(), full_len, &mut child_name, &mut child_len);
        if !parent.is_null() {
            dir_remove_entry(parent, child_name, child_len);
        }
        // Reset SHM data slot
        let shm_idx = (*inode).dev_type as usize;
        if shm_idx < max_shm_objects() {
            SHM_DATA!()[shm_idx].active = 0;
            SHM_DATA!()[shm_idx].num_pages = 0;
        }

        (*inode).active = 0;
        (*reply).label = SALTY_OK;
        false
    }
}

unsafe fn handle_ftruncate(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let length = (*msg).regs[1];

        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= (*cli).fds_cap as i32
            || (*(*cli).fds.add(fd as usize)).active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let fde = *(*cli).fds.add(fd as usize);

        if fde.fd_type == FD_TYPE_SHM {
            let inode = inode_by_ino(fde.inode);
            if inode.is_null() || (*inode).ftype != FTYPE_SHM {
                (*reply).label = SALTY_INVALID_OPERATION;
                return false;
            }

            let shm_idx = (*inode).dev_type as usize;
            if shm_idx >= max_shm_objects() {
                (*reply).label = SALTY_INVALID_OPERATION;
                return false;
            }

            let num_pages = ((length + 4095) / 4096) as u16;
            if num_pages as usize > max_shm_pages() {
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return false;
            }

            // Delegate frame allocation to mmsrv via MM_SHM_CREATE
            let shm = &raw mut SHM_DATA!()[shm_idx];

            {
                let mut mm_msg = SaltyMsg::zeroed();
                let mut mm_reply = SaltyMsg::zeroed();
                mm_msg.label = MM_SHM_CREATE;
                mm_msg.length = 2;
                mm_msg.regs[0] = shm_idx as u64;
                mm_msg.regs[1] = num_pages as u64;
                let err = ipc::call_ctx(
                    ipc_ctx(),
                    VFS_CAP_MMSRV_EP,
                    &raw const mm_msg,
                    &raw mut mm_reply,
                );
                if err != 0 || mm_reply.label != SALTY_OK {
                    (*reply).label = SALTY_OUT_OF_MEMORY;
                    return false;
                }
            }

            (*shm).num_pages = num_pages;
            (*inode).size = length;

            (*reply).label = SALTY_OK;
            return false;
        }

        // Regular file truncate
        let inode = inode_by_ino(fde.inode);
        if inode.is_null() || (*inode).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }
        if !(*inode).rw_data.is_null() && length < (*inode).size {
            chain_truncate((*inode).rw_data, length);
        }
        (*inode).size = length;
        (*reply).label = SALTY_OK;
        false
    }
}

// ======================================================================
// Link handlers
// ======================================================================

/// linkat(olddirfd, oldpath, newdirfd, newpath, flags)
/// IPC: regs[0]=old_len, regs[1..9]=oldpath(64B), regs[9]=new_len, regs[10..18]=newpath(64B)
unsafe fn handle_linkat(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let old_len = (*msg).regs[0] as u8;
        if old_len == 0 || old_len as usize > 64 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let new_len = (*msg).regs[9] as u8;
        if new_len == 0 || new_len as usize > 64 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Extract old path
        let mut old_path = [0u8; MAX_PATH_LEN];
        let src_old = &(*msg).regs[1] as *const u64 as *const u8;
        for i in 0..old_len as usize {
            old_path[i] = *src_old.add(i);
        }

        // Extract new path
        let mut new_path = [0u8; MAX_PATH_LEN];
        let src_new = &(*msg).regs[10] as *const u64 as *const u8;
        for i in 0..new_len as usize {
            new_path[i] = *src_new.add(i);
        }

        // Resolve old path to inode (follow symlinks)
        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Resolve old path (absolute or relative to cwd)
        let target = if old_path[0] == b'/' {
            resolve_path_raw(old_path.as_ptr(), old_len)
        } else {
            let mut cwd_len: usize = 0;
            while cwd_len < 128 && (*cli).cwd[cwd_len] != 0 { cwd_len += 1; }
            let total = cwd_len + 1 + old_len as usize;
            if total > MAX_PATH_LEN {
                (*reply).label = SALTY_NOT_FOUND;
                return;
            }
            let mut abs = [0u8; MAX_PATH_LEN];
            for i in 0..cwd_len { abs[i] = (*cli).cwd[i]; }
            abs[cwd_len] = b'/';
            for i in 0..old_len as usize { abs[cwd_len + 1 + i] = old_path[i]; }
            resolve_path_raw(abs.as_ptr(), total as u8)
        };
        if target.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        // Cannot hard-link directories
        if (*target).ftype == FTYPE_DIRECTORY {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        // Resolve new path parent (absolute or relative to cwd)
        let mut abs_new = [0u8; MAX_PATH_LEN];
        let abs_new_len: u8;
        if new_path[0] == b'/' {
            for i in 0..new_len as usize { abs_new[i] = new_path[i]; }
            abs_new_len = new_len;
        } else {
            let mut cwd_len: usize = 0;
            while cwd_len < 128 && (*cli).cwd[cwd_len] != 0 { cwd_len += 1; }
            let total = cwd_len + 1 + new_len as usize;
            if total > MAX_PATH_LEN {
                (*reply).label = SALTY_NOT_FOUND;
                return;
            }
            for i in 0..cwd_len { abs_new[i] = (*cli).cwd[i]; }
            abs_new[cwd_len] = b'/';
            for i in 0..new_len as usize { abs_new[cwd_len + 1 + i] = new_path[i]; }
            abs_new_len = total as u8;
        }

        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let new_parent = resolve_parent(abs_new.as_ptr(), abs_new_len, &mut child_name, &mut child_len);
        if new_parent.is_null() || (*new_parent).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        // Check new name doesn't already exist
        let existing = dir_find_entry(new_parent, child_name, child_len);
        if !existing.is_null() {
            (*reply).label = SALTY_ALREADY_EXISTS;
            return;
        }

        // Add new directory entry pointing to the same inode
        if dir_add_entry(new_parent, child_name, child_len, (*target).ino) != 0 {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        (*target).nlink += 1;
        (*reply).label = SALTY_OK;
    }
}

/// symlinkat(target, newdirfd, linkpath)
/// IPC: regs[0]=target_len, regs[1..9]=target(64B), regs[9]=link_len, regs[10..18]=link(64B)
unsafe fn handle_symlinkat(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        // Dual-path IPC: regs[1..9]=target(64B), regs[10..18]=link(64B)
        let target_len = (*msg).regs[0] as u8;
        if target_len == 0 || target_len > 64 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let mut target = [0u8; MAX_PATH_LEN];
        let raw_target = &(*msg).regs[1] as *const u64 as *const u8;
        for i in 0..target_len as usize {
            target[i] = *raw_target.add(i);
        }

        let link_len = (*msg).regs[9] as u8;
        if link_len == 0 || link_len > 64 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let mut link_path = [0u8; MAX_PATH_LEN];
        let raw_link = &(*msg).regs[10] as *const u64 as *const u8;
        for i in 0..link_len as usize {
            link_path[i] = *raw_link.add(i);
        }

        // Resolve parent of the link
        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent(link_path.as_ptr(), link_len, &mut child_name, &mut child_len);
        if parent.is_null() || (*parent).ftype != FTYPE_DIRECTORY || (*parent).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }
        if child_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Check that target name doesn't already exist
        let existing = dir_find_entry(parent, child_name, child_len);
        if !existing.is_null() {
            (*reply).label = SALTY_ALREADY_EXISTS;
            return;
        }

        // Allocate symlink target in pool
        let sym_data = alloc_symlink_target(target.as_ptr(), target_len);
        if sym_data.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // Allocate inode
        let inode = alloc_inode();
        if inode.is_null() {
            free_symlink_target(sym_data);
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        (*inode).ftype = FTYPE_SYMLINK;
        (*inode).mode = S_IFLNK_L | 0o777;
        (*inode).nlink = 1;
        (*inode).size = target_len as u64;
        (*inode).rw_data = sym_data;
        (*inode).parent_ino = (*parent).ino;

        dir_add_entry(parent, child_name, child_len, (*inode).ino);
        (*reply).label = SALTY_OK;
    }
}

/// readlinkat(dirfd, path) -> target
/// IPC in: regs[0]=path_len, regs[1..]=path
/// IPC out: regs[0]=target_len, regs[1..]=target
unsafe fn handle_readlinkat(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 0, path.as_mut_ptr());

        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) = normalize_path_for_client(
            badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };

        let inode = resolve_path_raw_nofollow(path_ptr, path_len);
        if inode.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        if (*inode).ftype != FTYPE_SYMLINK {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let (target, target_len) = symlink_target(inode);
        if target.is_null() || target_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        (*reply).label = SALTY_OK;
        (*reply).regs[0] = target_len as u64;
        (*reply).length = 1 + ((target_len as u64 + 7) / 8);
        let dst = &raw mut (*reply).regs[1] as *mut u8;
        for i in 0..target_len as usize {
            *dst.add(i) = *target.add(i);
        }
    }
}

/// lstat: stat without following final symlink
unsafe fn handle_lstat(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let mut abs_path = [0u8; MAX_PATH_LEN];
        let raw_len = extract_path(msg, 0, path.as_mut_ptr());
        if raw_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let Some((path_ptr, path_len)) = normalize_path_for_client(
            badge, path.as_ptr(), raw_len, abs_path.as_mut_ptr(),
        ) else {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        };
        let inode = resolve_path_raw_nofollow(path_ptr, path_len);
        if inode.is_null() {
            // Try /proc virtual paths
            if path_len >= 6 && *path_ptr == b'/' && *path_ptr.add(1) == b'p'
                && *path_ptr.add(2) == b'r' && *path_ptr.add(3) == b'o'
                && *path_ptr.add(4) == b'c' && *path_ptr.add(5) == b'/'
            {
                if handle_proc_stat(path_ptr, path_len, reply, badge) {
                    return;
                }
            }
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }
        fill_stat_reply(reply, inode);
    }
}

// ======================================================================
// /proc filesystem
// ======================================================================

/// Parse a decimal PID string (up to 10 digits). Returns (pid, true) or (0, false).
fn parse_pid(buf: &[u8]) -> (u32, bool) {
    if buf.is_empty() || buf.len() > 10 {
        return (0, false);
    }
    let mut val: u32 = 0;
    for &b in buf {
        if b < b'0' || b > b'9' {
            return (0, false);
        }
        val = val.wrapping_mul(10).wrapping_add((b - b'0') as u32);
    }
    (val, true)
}

/// Format u32 as decimal into buf. Returns number of bytes written.
fn fmt_u32(mut v: u32, buf: &mut [u8]) -> usize {
    if v == 0 {
        if !buf.is_empty() { buf[0] = b'0'; }
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    while v > 0 && len < 10 {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    for i in 0..len {
        if i < buf.len() {
            buf[i] = tmp[len - 1 - i];
        }
    }
    len
}

/// Format u64 as hex into buf. Returns number of bytes written.
fn fmt_u64_hex(mut v: u64, buf: &mut [u8]) -> usize {
    if v == 0 {
        if buf.len() >= 3 { buf[0] = b'0'; buf[1] = b'x'; buf[2] = b'0'; return 3; }
        return 0;
    }
    let mut tmp = [0u8; 16];
    let mut len = 0usize;
    while v > 0 && len < 16 {
        let d = (v & 0xf) as u8;
        tmp[len] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        v >>= 4;
        len += 1;
    }
    if buf.len() < len + 2 { return 0; }
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..len {
        buf[2 + i] = tmp[len - 1 - i];
    }
    len + 2
}

/// Query procmgr for list of PIDs. Returns count (up to 19).
unsafe fn proc_list_pids(pids: &mut [u32; 19]) -> usize {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_LIST_PIDS;
        msg.length = 0;
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_PROCMGR_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != SALTY_OK {
            return 0;
        }
        let count = reply.regs[19] as usize;
        let n = if count > 19 { 19 } else { count };
        for i in 0..n {
            pids[i] = reply.regs[i] as u32;
        }
        n
    }
}

/// Query procmgr for process info. Returns true on success.
unsafe fn proc_get_info(
    pid: u32, ppid: &mut u32, pgid: &mut u32, sid: &mut u32,
    state: &mut u8, name: &mut [u8; 32],
) -> bool {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_GET_PROC_INFO;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_PROCMGR_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != SALTY_OK {
            return false;
        }
        *ppid = reply.regs[1] as u32;
        *pgid = reply.regs[2] as u32;
        *sid = reply.regs[3] as u32;
        *state = reply.regs[4] as u8;
        let src = &reply.regs[5] as *const u64 as *const u8;
        for i in 0..32 {
            name[i] = *src.add(i);
        }
        true
    }
}

/// Query mmsrv for client memory stats. Returns true on success.
unsafe fn proc_get_mem_stats(
    pid: u32, heap_base: &mut u64, heap_current: &mut u64,
    region_count: &mut u64, total_pages: &mut u64,
) -> bool {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = MM_GET_CLIENT_STATS;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_MMSRV_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != SALTY_OK {
            return false;
        }
        *heap_base = reply.regs[0];
        *heap_current = reply.regs[1];
        *region_count = reply.regs[2];
        *total_pages = reply.regs[3];
        true
    }
}

/// Generate /proc/<pid>/status content. Returns bytes written.
unsafe fn proc_gen_status(pid: u32, buf: *mut u8, buf_size: usize) -> usize {
    unsafe {
        let mut ppid: u32 = 0;
        let mut pgid: u32 = 0;
        let mut sid: u32 = 0;
        let mut state: u8 = 0;
        let mut name = [0u8; 32];
        if !proc_get_info(pid, &mut ppid, &mut pgid, &mut sid, &mut state, &mut name) {
            return 0;
        }

        // Find name length
        let mut name_len = 0usize;
        while name_len < 32 && name[name_len] != 0 { name_len += 1; }
        if name_len == 0 { name[0] = b'?'; name_len = 1; }

        let mut pos = 0usize;
        let mut tmp = [0u8; 12];

        // "Name:\t<name>\n"
        let hdr = b"Name:\t";
        for b in hdr { if pos < buf_size { *buf.add(pos) = *b; pos += 1; } }
        for i in 0..name_len { if pos < buf_size { *buf.add(pos) = name[i]; pos += 1; } }
        if pos < buf_size { *buf.add(pos) = b'\n'; pos += 1; }

        // "State:\t<R/Z/T>\n"
        let hdr = b"State:\t";
        for b in hdr { if pos < buf_size { *buf.add(pos) = *b; pos += 1; } }
        let st_char = match state { 1 => b'R', 2 => b'Z', 3 => b'T', _ => b'?' };
        if pos < buf_size { *buf.add(pos) = st_char; pos += 1; }
        if pos < buf_size { *buf.add(pos) = b'\n'; pos += 1; }

        // "Pid:\t<pid>\n"
        let hdr = b"Pid:\t";
        for b in hdr { if pos < buf_size { *buf.add(pos) = *b; pos += 1; } }
        let n = fmt_u32(pid, &mut tmp);
        for i in 0..n { if pos < buf_size { *buf.add(pos) = tmp[i]; pos += 1; } }
        if pos < buf_size { *buf.add(pos) = b'\n'; pos += 1; }

        // "PPid:\t<ppid>\n"
        let hdr = b"PPid:\t";
        for b in hdr { if pos < buf_size { *buf.add(pos) = *b; pos += 1; } }
        let n = fmt_u32(ppid, &mut tmp);
        for i in 0..n { if pos < buf_size { *buf.add(pos) = tmp[i]; pos += 1; } }
        if pos < buf_size { *buf.add(pos) = b'\n'; pos += 1; }

        // "Pgid:\t<pgid>\n"
        let hdr = b"Pgid:\t";
        for b in hdr { if pos < buf_size { *buf.add(pos) = *b; pos += 1; } }
        let n = fmt_u32(pgid, &mut tmp);
        for i in 0..n { if pos < buf_size { *buf.add(pos) = tmp[i]; pos += 1; } }
        if pos < buf_size { *buf.add(pos) = b'\n'; pos += 1; }

        // "Sid:\t<sid>\n"
        let hdr = b"Sid:\t";
        for b in hdr { if pos < buf_size { *buf.add(pos) = *b; pos += 1; } }
        let n = fmt_u32(sid, &mut tmp);
        for i in 0..n { if pos < buf_size { *buf.add(pos) = tmp[i]; pos += 1; } }
        if pos < buf_size { *buf.add(pos) = b'\n'; pos += 1; }

        pos
    }
}

/// Generate /proc/<pid>/stat content (single-line). Returns bytes written.
unsafe fn proc_gen_stat(pid: u32, buf: *mut u8, buf_size: usize) -> usize {
    unsafe {
        let mut ppid: u32 = 0;
        let mut pgid: u32 = 0;
        let mut sid: u32 = 0;
        let mut state: u8 = 0;
        let mut name = [0u8; 32];
        if !proc_get_info(pid, &mut ppid, &mut pgid, &mut sid, &mut state, &mut name) {
            return 0;
        }

        let mut name_len = 0usize;
        while name_len < 32 && name[name_len] != 0 { name_len += 1; }
        if name_len == 0 { name[0] = b'?'; name_len = 1; }

        let mut pos = 0usize;
        let mut tmp = [0u8; 12];

        // "<pid> (<name>) <state> <ppid> <pgid> <sid>\n"
        let n = fmt_u32(pid, &mut tmp);
        for i in 0..n { if pos < buf_size { *buf.add(pos) = tmp[i]; pos += 1; } }
        if pos < buf_size { *buf.add(pos) = b' '; pos += 1; }
        if pos < buf_size { *buf.add(pos) = b'('; pos += 1; }
        for i in 0..name_len { if pos < buf_size { *buf.add(pos) = name[i]; pos += 1; } }
        if pos < buf_size { *buf.add(pos) = b')'; pos += 1; }
        if pos < buf_size { *buf.add(pos) = b' '; pos += 1; }
        let st_char = match state { 1 => b'R', 2 => b'Z', 3 => b'T', _ => b'?' };
        if pos < buf_size { *buf.add(pos) = st_char; pos += 1; }
        if pos < buf_size { *buf.add(pos) = b' '; pos += 1; }
        let n = fmt_u32(ppid, &mut tmp);
        for i in 0..n { if pos < buf_size { *buf.add(pos) = tmp[i]; pos += 1; } }
        if pos < buf_size { *buf.add(pos) = b' '; pos += 1; }
        let n = fmt_u32(pgid, &mut tmp);
        for i in 0..n { if pos < buf_size { *buf.add(pos) = tmp[i]; pos += 1; } }
        if pos < buf_size { *buf.add(pos) = b' '; pos += 1; }
        let n = fmt_u32(sid, &mut tmp);
        for i in 0..n { if pos < buf_size { *buf.add(pos) = tmp[i]; pos += 1; } }
        if pos < buf_size { *buf.add(pos) = b'\n'; pos += 1; }

        pos
    }
}

/// Handle open for /proc paths. Creates temporary proc file inode.
/// Returns true if handled (and reply is set), false if not a /proc path.
unsafe fn handle_proc_open(
    path: *const u8, path_len: u8, reply: *mut SaltyMsg, badge: u64,
) -> bool {
    unsafe {
        // Check if path starts with "/proc/"
        if path_len < 6 { return false; }
        let proc_prefix = b"/proc/";
        for i in 0..6 {
            if *path.add(i) != proc_prefix[i] { return false; }
        }

        let rest = path.add(6);
        let rest_len = path_len - 6;

        // Check for /proc/self -> resolve to client's PID
        let is_self_prefix = rest_len >= 4
            && *rest == b's' && *rest.add(1) == b'e'
            && *rest.add(2) == b'l' && *rest.add(3) == b'f';

        let (pid, file_offset) = if is_self_prefix && (rest_len == 4 || *rest.add(4) == b'/') {
            // /proc/self/... — get client PID from procmgr
            let mut msg = SaltyMsg::zeroed();
            let mut pm_reply = SaltyMsg::zeroed();
            msg.label = POSIX_PM_GETPID;
            msg.length = 0;
            let ctx = ipc_ctx();
            // Use the client's badge to identify them to procmgr
            // Actually, VFS needs to ask procmgr about this badge.
            // For now use a direct getpid approach via badge lookup.
            // The procmgr identifies callers by badge. We need the PID for
            // the requesting client. We have their badge in `badge`.
            // Use PM_GETPGID_BADGE which takes a badge and returns info.
            // Actually, let's do a simpler approach: call PM_GET_PROC_INFO
            // We don't have the PID yet... Let's use the PM_LIST_PIDS and
            // match by iterating. This is complex — instead, let's just use
            // PID 1 as fallback for self for now.
            //
            // Actually, let's ask procmgr for getpid using the client badge.
            // PM_REGISTER takes badge→pid mapping. PM_GETPGID_BADGE takes badge in regs[0].
            // But what returns PID from badge? Let's check...
            // The simplest: iterate clients and find the client by badge,
            // then use client's stored info.
            //
            // Actually we can just forward the call to procmgr as if from
            // the client. But VFS calls procmgr with its own badge.
            //
            // Simpler approach: just look up the badge in our client table
            // and see if they have a PID recorded. Or we can just not support
            // /proc/self initially and require numeric PIDs.
            let cli = get_client_noalloc(badge);
            if cli.is_null() {
                (*reply).label = SALTY_NOT_FOUND;
                return true;
            }
            // Client badge encodes PID: badge = pid
            let client_pid = (badge & 0xFFFF) as u32;
            if rest_len == 4 {
                // /proc/self (just the dir itself)
                (client_pid, 4u8)
            } else {
                (client_pid, 5u8) // skip "self/"
            }
        } else {
            // /proc/<pid>/... — parse numeric PID
            let mut pid_end = 0u8;
            while (pid_end as usize) < rest_len as usize && *rest.add(pid_end as usize) != b'/' {
                pid_end += 1;
            }
            let mut pid_buf = [0u8; 10];
            for i in 0..pid_end as usize {
                if i < 10 { pid_buf[i] = *rest.add(i); }
            }
            let (pid, ok) = parse_pid(&pid_buf[..pid_end as usize]);
            if !ok {
                (*reply).label = SALTY_NOT_FOUND;
                return true;
            }
            (pid, pid_end)
        };

        // What file under /proc/<pid>/?
        let after_pid = rest.add(file_offset as usize);
        let after_len = if file_offset < rest_len { rest_len - file_offset } else { 0 };

        if after_len == 0 {
            // /proc/<pid> — the directory itself; open as dir
            // Allocate temp proc inode
            let inode = alloc_inode();
            if inode.is_null() {
                (*reply).label = SALTY_OUT_OF_MEMORY;
                return true;
            }
            (*inode).ftype = FTYPE_PROC_FILE;
            (*inode).dev_type = PROC_FILE_PID_DIR;
            (*inode).mode = S_IFDIR_L | 0o555;
            (*inode).readonly = 1;
            (*inode).nlink = 0; // temp inode — freed when last FD closes
            (*inode).size = pid as u64; // store PID in size field

            let cli = get_client(badge);
            if cli.is_null() { (*reply).label = SALTY_OUT_OF_MEMORY; (*inode).active = 0; return true; }
            for fd in 0..(*cli).fds_cap as usize {
                if (*(*cli).fds.add(fd)).active == 0 {
                    (*(*cli).fds.add(fd)).active = 1;
                    (*(*cli).fds.add(fd)).fd_type = FD_TYPE_DIR;
                    (*(*cli).fds.add(fd)).inode = (*inode).ino;
                    (*(*cli).fds.add(fd)).offset = 0;
                    (*(*cli).fds.add(fd)).dir_cursor = 0;
                    inode_open((*inode).ino);
                    (*reply).label = SALTY_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = fd as u64;
                    return true;
                }
            }
            (*inode).active = 0;
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return true;
        }

        // Skip leading '/'
        let (file_name, file_name_len) = if after_len > 0 && *after_pid == b'/' {
            (after_pid.add(1), after_len - 1)
        } else {
            (after_pid, after_len)
        };

        // Determine file type
        let proc_type = if file_name_len == 6 && mem_eq(file_name, b"status".as_ptr(), 6) {
            PROC_FILE_STATUS
        } else if file_name_len == 4 && mem_eq(file_name, b"stat".as_ptr(), 4) {
            PROC_FILE_STAT
        } else if file_name_len == 4 && mem_eq(file_name, b"maps".as_ptr(), 4) {
            PROC_FILE_MAPS
        } else {
            (*reply).label = SALTY_NOT_FOUND;
            return true;
        };

        // Allocate temporary inode for this proc file
        let inode = alloc_inode();
        if inode.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return true;
        }
        (*inode).ftype = FTYPE_PROC_FILE;
        (*inode).dev_type = proc_type;
        (*inode).mode = S_IFREG_L | 0o444;
        (*inode).readonly = 1;
        (*inode).nlink = 0; // temp inode — freed when last FD closes
        (*inode).size = pid as u64; // store PID in size field

        let cli = get_client(badge);
        if cli.is_null() { (*reply).label = SALTY_OUT_OF_MEMORY; (*inode).active = 0; return true; }
        for fd in 0..(*cli).fds_cap as usize {
            if (*(*cli).fds.add(fd)).active == 0 {
                (*(*cli).fds.add(fd)).active = 1;
                (*(*cli).fds.add(fd)).fd_type = FD_TYPE_FILE;
                (*(*cli).fds.add(fd)).inode = (*inode).ino;
                (*(*cli).fds.add(fd)).offset = 0;
                (*(*cli).fds.add(fd)).dir_cursor = 0;
                (*(*cli).fds.add(fd)).flags = 0; // O_RDONLY
                inode_open((*inode).ino);
                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = fd as u64;
                return true;
            }
        }
        (*inode).active = 0;
        (*reply).label = SALTY_OUT_OF_MEMORY;
        true
    }
}

/// Simple memory comparison (no libc).
fn mem_eq(a: *const u8, b: *const u8, len: usize) -> bool {
    for i in 0..len {
        unsafe {
            if *a.add(i) != *b.add(i) { return false; }
        }
    }
    true
}

/// Handle stat/lstat for /proc virtual paths that don't resolve as real inodes.
/// Returns true if the path was handled (even if error).
unsafe fn handle_proc_stat(
    path: *const u8, path_len: u8, reply: *mut SaltyMsg, badge: u64,
) -> bool {
    unsafe {
        // Path must start with "/proc/" (caller already checked)
        if path_len < 6 { return false; }

        let rest = path.add(6);
        let rest_len = path_len - 6;

        // Parse "self" or numeric PID
        let is_self_prefix = rest_len >= 4
            && *rest == b's' && *rest.add(1) == b'e'
            && *rest.add(2) == b'l' && *rest.add(3) == b'f';

        let (pid, file_offset) = if is_self_prefix && (rest_len == 4 || *rest.add(4) == b'/') {
            let client_pid = (badge & 0xFFFF) as u32;
            if rest_len == 4 { (client_pid, 4u8) } else { (client_pid, 5u8) }
        } else {
            let mut pid_end = 0u8;
            while (pid_end as usize) < rest_len as usize && *rest.add(pid_end as usize) != b'/' {
                pid_end += 1;
            }
            let (pid, ok) = parse_pid(&core::slice::from_raw_parts(rest, pid_end as usize));
            if !ok {
                (*reply).label = SALTY_NOT_FOUND;
                return true;
            }
            (pid, pid_end)
        };

        let after_pid = rest.add(file_offset as usize);
        let after_len = if file_offset < rest_len { rest_len - file_offset } else { 0 };

        if after_len == 0 {
            // /proc/<pid> — directory
            (*reply).label = SALTY_OK;
            (*reply).length = 8;
            (*reply).regs[0] = pid as u64; // ino
            (*reply).regs[1] = (S_IFDIR_L | 0o555) as u64; // mode
            (*reply).regs[2] = 2; // nlink
            (*reply).regs[3] = 0; // size
            (*reply).regs[4] = 0; // uid
            (*reply).regs[5] = 0; // gid
            (*reply).regs[6] = 0; // mtime
            (*reply).regs[7] = FTYPE_PROC_FILE as u64;
            return true;
        }

        let (file_name, file_name_len) = if after_len > 0 && *after_pid == b'/' {
            (after_pid.add(1), after_len - 1)
        } else {
            (after_pid, after_len)
        };

        let is_known = (file_name_len == 6 && mem_eq(file_name, b"status".as_ptr(), 6))
            || (file_name_len == 4 && mem_eq(file_name, b"stat".as_ptr(), 4))
            || (file_name_len == 4 && mem_eq(file_name, b"maps".as_ptr(), 4));

        if !is_known {
            (*reply).label = SALTY_NOT_FOUND;
            return true;
        }

        // Regular file stat
        (*reply).label = SALTY_OK;
        (*reply).length = 8;
        (*reply).regs[0] = 0; // ino (virtual)
        (*reply).regs[1] = (S_IFREG_L | 0o444) as u64; // mode
        (*reply).regs[2] = 1; // nlink
        (*reply).regs[3] = 0; // size (unknown for virtual files)
        (*reply).regs[4] = 0; // uid
        (*reply).regs[5] = 0; // gid
        (*reply).regs[6] = 0; // mtime
        (*reply).regs[7] = FTYPE_PROC_FILE as u64;
        true
    }
}

/// Handle read for FTYPE_PROC_FILE inodes.
/// Generates content on-the-fly from procmgr/mmsrv.
unsafe fn handle_proc_read(
    inode: *const RamfsInode, offset: u64, reply: *mut SaltyMsg,
) {
    unsafe {
        let pid = (*inode).size as u32;
        let proc_type = (*inode).dev_type;

        // Generate content into a stack buffer
        let mut content = [0u8; 512];
        let content_len = match proc_type {
            PROC_FILE_STATUS => proc_gen_status(pid, content.as_mut_ptr(), 512),
            PROC_FILE_STAT => proc_gen_stat(pid, content.as_mut_ptr(), 512),
            PROC_FILE_MAPS => {
                // /proc/<pid>/maps — query mmsrv for memory stats
                let mut heap_base: u64 = 0;
                let mut heap_current: u64 = 0;
                let mut region_count: u64 = 0;
                let mut total_pages: u64 = 0;
                if proc_get_mem_stats(pid, &mut heap_base, &mut heap_current,
                    &mut region_count, &mut total_pages)
                {
                    let mut pos = 0usize;
                    let mut tmp = [0u8; 20];
                    // "heap: <base>-<current> <pages> pages\n"
                    let hdr = b"heap: ";
                    for b in hdr { if pos < 512 { content[pos] = *b; pos += 1; } }
                    let n = fmt_u64_hex(heap_base, &mut tmp);
                    for i in 0..n { if pos < 512 { content[pos] = tmp[i]; pos += 1; } }
                    if pos < 512 { content[pos] = b'-'; pos += 1; }
                    let n = fmt_u64_hex(heap_current, &mut tmp);
                    for i in 0..n { if pos < 512 { content[pos] = tmp[i]; pos += 1; } }
                    if pos < 512 { content[pos] = b'\n'; pos += 1; }
                    // "regions: <count>\n"
                    let hdr = b"regions: ";
                    for b in hdr { if pos < 512 { content[pos] = *b; pos += 1; } }
                    let n = fmt_u32(region_count as u32, &mut tmp);
                    for i in 0..n { if pos < 512 { content[pos] = tmp[i]; pos += 1; } }
                    if pos < 512 { content[pos] = b'\n'; pos += 1; }
                    // "pages: <total>\n"
                    let hdr = b"pages: ";
                    for b in hdr { if pos < 512 { content[pos] = *b; pos += 1; } }
                    let n = fmt_u32(total_pages as u32, &mut tmp);
                    for i in 0..n { if pos < 512 { content[pos] = tmp[i]; pos += 1; } }
                    if pos < 512 { content[pos] = b'\n'; pos += 1; }
                    pos
                } else {
                    0
                }
            }
            _ => 0,
        };

        if offset as usize >= content_len {
            // EOF
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }

        let available = content_len - offset as usize;
        let max_ipc = 152; // 19 regs * 8 bytes
        let to_copy = if available < max_ipc { available } else { max_ipc };

        let dst = &mut (*reply).regs[1] as *mut u64 as *mut u8;
        for i in 0..to_copy {
            *dst.add(i) = content[offset as usize + i];
        }
        (*reply).label = SALTY_OK;
        (*reply).length = 1 + ((to_copy as u64 + 7) / 8);
        (*reply).regs[0] = to_copy as u64;
    }
}

/// Handle readdir for /proc root — returns PID entries.
unsafe fn handle_proc_readdir(
    inode: *const RamfsInode, cursor: u32, reply: *mut SaltyMsg,
) {
    unsafe {
        if (*inode).dev_type == PROC_FILE_ROOT {
            // /proc root readdir: list PIDs + "self"
            let mut pids = [0u32; 19];
            let count = proc_list_pids(&mut pids);

            // cursor 0 = "self", then PIDs
            if cursor == 0 {
                // Return "self" entry
                (*reply).label = SALTY_OK;
                (*reply).regs[0] = 4; // name_len = 4
                (*reply).regs[1] = cursor as u64 + 1; // next cursor
                (*reply).regs[2] = 0; // ino
                (*reply).regs[3] = 10; // DT_LNK
                let dst = &mut (*reply).regs[4] as *mut u64 as *mut u8;
                *dst = b's'; *dst.add(1) = b'e'; *dst.add(2) = b'l'; *dst.add(3) = b'f';
                (*reply).length = 5;
                return;
            }

            let idx = (cursor - 1) as usize;
            if idx >= count {
                // No more entries
                (*reply).label = SALTY_OK;
                (*reply).regs[0] = 0; // name_len = 0 → end
                (*reply).length = 1;
                return;
            }

            // Format PID as string
            let mut name_buf = [0u8; 10];
            let name_len = fmt_u32(pids[idx], &mut name_buf);

            (*reply).label = SALTY_OK;
            (*reply).regs[0] = name_len as u64;
            (*reply).regs[1] = cursor as u64 + 1;
            (*reply).regs[2] = pids[idx] as u64; // ino = pid
            (*reply).regs[3] = 4; // DT_DIR
            let dst = &mut (*reply).regs[4] as *mut u64 as *mut u8;
            for i in 0..name_len { *dst.add(i) = name_buf[i]; }
            (*reply).length = 5;
        } else if (*inode).dev_type == PROC_FILE_PID_DIR {
            // /proc/<pid> readdir: list status, stat, maps
            let entries: &[&[u8]] = &[b"status", b"stat", b"maps"];
            let cursor_idx = cursor as usize;
            if cursor_idx >= entries.len() {
                (*reply).label = SALTY_OK;
                (*reply).regs[0] = 0;
                (*reply).length = 1;
                return;
            }
            let entry = entries[cursor_idx];
            (*reply).label = SALTY_OK;
            (*reply).regs[0] = entry.len() as u64;
            (*reply).regs[1] = cursor as u64 + 1;
            (*reply).regs[2] = 0; // ino
            (*reply).regs[3] = 8; // DT_REG
            let dst = &mut (*reply).regs[4] as *mut u64 as *mut u8;
            for i in 0..entry.len() { *dst.add(i) = entry[i]; }
            (*reply).length = 5;
        } else {
            (*reply).label = SALTY_NOT_FOUND;
        }
    }
}

// ======================================================================
// Entry point
// ======================================================================

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    puts(b"[VFS] SaltyOS VFS server starting\n");

    let err = salty::invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
    if err != 0 {
        { let mut lb = LineBuf::new(); lb.str(b"[VFS] FAIL: set IPC buffer err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush(); }
        idle();
    }
    unsafe {
        ipc::ipc_context_init(ipc_ctx(), IPC_BUF_VADDR as *mut IpcBuffer);
    }

    puts(b"[VFS] IPC buffer ready\n");

    // Initialize per-process slot allocator from RTLD-exported globals
    unsafe {
        let base = *(&raw const salty::__salty_slot_base);
        let count = *(&raw const salty::__salty_slot_count);
        let cspace_ntfn = *(&raw const salty::__salty_cspace_ntfn);
        if base != 0 {
            salty::slot_alloc::slot_alloc_init(base, count, cspace_ntfn);
        } else {
            puts(b"[VFS] FATAL: slot pool not provided by RTLD/auxv\n");
            idle();
        }
    }

    // Initialize mmsrv client (must happen before posix_mmap is used)
    unsafe {
        salty::posix_mm::posix_mm_init(VFS_CAP_MMSRV_EP);
    }

    unsafe {
        let derr = init_dynamic_state_storage();
        if derr != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[VFS] FAIL: state storage init err=");
            lb.hex(derr as u64);
            lb.str(b"\n");
            lb.flush();
            idle();
        }
    }

    unsafe {
        urandom_init();
        init_ramfs();
        init_fb_info();
    }

    puts(b"[VFS] Filesystem ready\n");

    // Register with name server
    if VFS_CAP_NAMESERV_EP != 0 {
        let mut reg_msg = SaltyMsg::zeroed();
        let mut reg_reply = SaltyMsg::zeroed();
        let svc_name = b"vfs";
        reg_msg.label = POSIX_NS_REGISTER;
        reg_msg.regs[0] = svc_name.len() as u64;
        reg_msg.length = 1 + (svc_name.len() as u64 + 7) / 8;
        let ns_dst = &raw mut reg_msg.regs[1] as *mut u8;
        unsafe {
            for i in 0..svc_name.len() {
                *ns_dst.add(i) = svc_name[i];
            }
        }

        unsafe {
            ipc::set_send_cap_ctx(ipc_ctx(), 0, CAP_SERVER_EP);
            let err = ipc::call_ctx(ipc_ctx(), VFS_CAP_NAMESERV_EP, &raw const reg_msg, &raw mut reg_reply);
            if err == 0 && reg_reply.label == SALTY_OK {
                puts(b"[VFS] registered with nameserv\n");
            } else {
                puts(b"[VFS] WARN: nameserv registration failed\n");
            }
        }
    }

    // Bind PTY notification to VFS TCB for data-ready wake-ups from ttyd
    {
        let err = salty::invoke::tcb_bind_notification(CAP_SELF_TCB, VFS_CAP_PTY_NTFN);
        if err == 0 {
            puts(b"[VFS] PTY notification bound to TCB\n");
        } else {
            puts(b"[VFS] WARN: PTY notification bind failed\n");
        }
    }

    signal_ready();

    // Initial recv
    let mut msg = SaltyMsg::zeroed();
    let mut badge: u64 = 0;

    let err = unsafe { ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge) };
    if err != 0 {
        puts(b"[VFS] initial recv failed\n");
        idle();
    }

    // Server loop — supports deferred replies via save_caller pattern.
    // Handlers return bool: true = deferred (skip reply), false = reply now.
    // Bound notification from ttyd (PTY data-ready) wakes recv/reply_recv
    // with badge = notification word, msg.length = 0.
    loop {
        let mut reply = SaltyMsg::zeroed();
        let mut skip_reply = false;
        // Check for bound notification wake-up (PTY data ready from ttyd).
        // Bound notifications have label=0 AND length=0; regular IPC with
        // length=0 (e.g. socketpair) will have label != 0.
        if msg.length == 0 && msg.label == 0 && badge != 0 {
            unsafe { handle_pty_notification(badge); }
            skip_reply = true; // no client to reply to
        } else {
        unsafe {
            match msg.label {
                VFS_OPEN => { handle_open(&raw const msg, &raw mut reply, badge); }
                VFS_READ => {
                    let fd = msg.regs[0] as i32;
                    let cli = get_client(badge);
                    if !cli.is_null() && fd >= 0 && fd < (*cli).fds_cap as i32
                        && (*(*cli).fds.add(fd as usize)).active != 0
                    {
                        match (*(*cli).fds.add(fd as usize)).fd_type {
                            FD_TYPE_SOCKET => {
                                skip_reply = handle_socket_read(
                                    (*cli).fds.add(fd as usize), &raw mut reply, badge);
                            }
                            FD_TYPE_PIPE => {
                                skip_reply = handle_pipe_read(
                                    &raw const msg, (*cli).fds.add(fd as usize), &raw mut reply, badge);
                            }
                            FD_TYPE_DEVICE => {
                                if (*(*cli).fds.add(fd as usize)).dev_type == DEV_PTY_SLAVE {
                                    skip_reply = handle_pty_dev_read(
                                        &raw const msg, (*cli).fds.add(fd as usize),
                                        &raw mut reply, badge);
                                } else {
                                    handle_read(&raw const msg, &raw mut reply, badge);
                                }
                            }
                            FD_TYPE_MOUNT => {
                                let fde = &mut *(*cli).fds.add(fd as usize);
                                let mount_idx = fde.dev_type as usize;
                                let remote_ino = fde.sock_id as u64;
                                let mut count = msg.regs[1];
                                if count > 152 { count = 152; }
                                mount_read_inline(
                                    mount_idx, remote_ino, fde.offset, count,
                                    &raw mut reply);
                                if reply.label == SALTY_OK {
                                    let bytes_read = reply.regs[0];
                                    fde.offset += bytes_read;
                                }
                            }
                            _ => {
                                handle_read(&raw const msg, &raw mut reply, badge);
                            }
                        }
                    } else {
                        handle_read(&raw const msg, &raw mut reply, badge);
                    }
                }
                VFS_WRITE => {
                    let fd = msg.regs[0] as i32;
                    let cli = get_client(badge);
                    if !cli.is_null() && fd >= 0 && fd < (*cli).fds_cap as i32
                        && (*(*cli).fds.add(fd as usize)).active != 0
                    {
                        match (*(*cli).fds.add(fd as usize)).fd_type {
                            FD_TYPE_SOCKET => {
                                skip_reply = handle_socket_write(
                                    &raw const msg, (*cli).fds.add(fd as usize), &raw mut reply);
                            }
                            FD_TYPE_PIPE => {
                                skip_reply = handle_pipe_write(
                                    &raw const msg, (*cli).fds.add(fd as usize), &raw mut reply, badge);
                            }
                            _ => {
                                handle_write(&raw const msg, &raw mut reply, badge);
                            }
                        }
                    } else {
                        handle_write(&raw const msg, &raw mut reply, badge);
                    }
                }
                VFS_CLOSE => {
                    let fd = msg.regs[0] as i32;
                    let cli = get_client(badge);
                    if !cli.is_null() && fd >= 0 && fd < (*cli).fds_cap as i32
                        && (*(*cli).fds.add(fd as usize)).active != 0
                    {
                        match (*(*cli).fds.add(fd as usize)).fd_type {
                            FD_TYPE_SOCKET => {
                                close_socket((*cli).fds.add(fd as usize));
                            }
                            FD_TYPE_PIPE => {
                                close_pipe((*cli).fds.add(fd as usize));
                            }
                            FD_TYPE_EPOLL => {
                                let ep_idx = (*(*cli).fds.add(fd as usize)).sock_id as usize;
                                if ep_idx < max_epoll_instances() {
                                    EPOLLS!()[ep_idx].active = 0;
                                }
                            }
                            _ => {}
                        }
                    }
                    handle_close(&raw const msg, &raw mut reply, badge);
                }
                VFS_STAT => { handle_stat(&raw const msg, &raw mut reply, badge); }
                VFS_LSEEK => { handle_lseek(&raw const msg, &raw mut reply, badge); }
                VFS_FSTAT => { handle_fstat(&raw const msg, &raw mut reply, badge); }
                VFS_ACCESS => { handle_access(&raw const msg, &raw mut reply, badge); }
                VFS_UNLINK => { handle_unlink(&raw const msg, &raw mut reply, badge); }
                VFS_RENAME => { handle_rename(&raw const msg, &raw mut reply, badge); }
                VFS_MKDIR => { handle_mkdir(&raw const msg, &raw mut reply, badge); }
                VFS_RMDIR => { handle_rmdir(&raw const msg, &raw mut reply, badge); }
                VFS_OPENDIR => { handle_opendir(&raw const msg, &raw mut reply, badge); }
                VFS_READDIR => {
                    let fd = msg.regs[0] as i32;
                    let cli = get_client(badge);
                    if !cli.is_null() && fd >= 0 && fd < (*cli).fds_cap as i32
                        && (*(*cli).fds.add(fd as usize)).active != 0
                        && (*(*cli).fds.add(fd as usize)).fd_type == FD_TYPE_MOUNT
                    {
                        let fde = &mut *(*cli).fds.add(fd as usize);
                        let mount_idx = fde.dev_type as usize;
                        let remote_ino = fde.sock_id as u64;
                        mount_readdir(mount_idx, fde as *mut FdEntry, remote_ino, &raw mut reply);
                    } else {
                        handle_readdir(&raw const msg, &raw mut reply, badge);
                    }
                }
                VFS_LSTAT => { handle_lstat(&raw const msg, &raw mut reply, badge); }
                VFS_POLL => {
                    skip_reply = handle_poll(&raw const msg, &raw mut reply, badge);
                }
                VFS_SHM_OPEN => {
                    skip_reply = handle_shm_open(&raw const msg, &raw mut reply, badge);
                }
                VFS_SHM_UNLINK => {
                    skip_reply = handle_shm_unlink(&raw const msg, &raw mut reply);
                }
                VFS_FTRUNCATE => {
                    skip_reply = handle_ftruncate(&raw const msg, &raw mut reply, badge);
                }
                VFS_SOCKET => {
                    skip_reply = handle_socket(&raw const msg, &raw mut reply, badge);
                }
                VFS_BIND => {
                    skip_reply = handle_bind(&raw const msg, &raw mut reply, badge);
                }
                VFS_LISTEN => {
                    skip_reply = handle_listen(&raw const msg, &raw mut reply, badge);
                }
                VFS_ACCEPT => {
                    skip_reply = handle_accept(&raw const msg, &raw mut reply, badge);
                }
                VFS_CONNECT => {
                    skip_reply = handle_connect(&raw const msg, &raw mut reply, badge);
                }
                VFS_SENDMSG => {
                    skip_reply = handle_sendmsg(&raw const msg, &raw mut reply, badge);
                }
                VFS_RECVMSG => {
                    skip_reply = handle_recvmsg(&raw const msg, &raw mut reply, badge);
                }
                VFS_SOCKPAIR => {
                    skip_reply = handle_sockpair(&raw const msg, &raw mut reply, badge);
                }
                VFS_SHUTDOWN => {
                    skip_reply = handle_shutdown(&raw const msg, &raw mut reply, badge);
                }
                VFS_PIPE => {
                    handle_pipe(&raw const msg, &raw mut reply, badge);
                }
                VFS_DUP => {
                    handle_dup(&raw const msg, &raw mut reply, badge);
                }
                VFS_DUP2 => {
                    handle_dup2(&raw const msg, &raw mut reply, badge);
                }
                VFS_CLONE_FDS => {
                    handle_clone_fds(&raw const msg, &raw mut reply);
                }
                VFS_ISATTY => {
                    handle_isatty(&raw const msg, &raw mut reply, badge);
                }
                VFS_IOCTL => {
                    handle_ioctl(&raw const msg, &raw mut reply, badge);
                }
                VFS_FCNTL => {
                    handle_fcntl(&raw const msg, &raw mut reply, badge);
                }
                VFS_CHDIR => {
                    handle_chdir(&raw const msg, &raw mut reply, badge);
                }
                VFS_GETCWD => {
                    handle_getcwd(&raw const msg, &raw mut reply, badge);
                }
                VFS_TCGETATTR => {
                    handle_tcgetattr(&raw const msg, &raw mut reply, badge);
                }
                VFS_TCSETATTR => {
                    handle_tcsetattr(&raw const msg, &raw mut reply, badge);
                }
                VFS_DUP3 => {
                    handle_dup3(&raw const msg, &raw mut reply, badge);
                }
                VFS_MKFIFO => {
                    handle_mkfifo(&raw const msg, &raw mut reply, badge);
                }
                VFS_EPOLL_CREATE => {
                    handle_epoll_create(&raw mut reply, badge);
                }
                VFS_EPOLL_CTL => {
                    handle_epoll_ctl(&raw const msg, &raw mut reply, badge);
                }
                VFS_EPOLL_WAIT => {
                    skip_reply = handle_epoll_wait(&raw const msg, &raw mut reply, badge);
                }
                VFS_MMAP => {
                    handle_mmap(&raw const msg, &raw mut reply, badge);
                }
                VFS_OPENAT => {
                    handle_openat(&raw const msg, &raw mut reply, badge);
                }
                VFS_FSTATAT => {
                    handle_fstatat(&raw const msg, &raw mut reply, badge);
                }
                VFS_UNLINKAT => {
                    handle_unlinkat(&raw const msg, &raw mut reply, badge);
                }
                VFS_RENAMEAT => {
                    handle_renameat(&raw const msg, &raw mut reply, badge);
                }
                VFS_MKDIRAT => {
                    handle_mkdirat(&raw const msg, &raw mut reply, badge);
                }
                VFS_FACCESSAT => {
                    handle_faccessat(&raw const msg, &raw mut reply, badge);
                }
                VFS_FCHMODAT => {
                    handle_fchmodat(&raw const msg, &raw mut reply, badge);
                }
                VFS_FCHOWNAT => {
                    handle_fchownat(&raw const msg, &raw mut reply, badge);
                }
                VFS_LINKAT => {
                    handle_linkat(&raw const msg, &raw mut reply, badge);
                }
                VFS_SYMLINKAT => {
                    handle_symlinkat(&raw const msg, &raw mut reply, badge);
                }
                VFS_READLINKAT => {
                    handle_readlinkat(&raw const msg, &raw mut reply, badge);
                }
                VFS_UTIMENSAT => {
                    handle_utimensat(&raw const msg, &raw mut reply, badge);
                }
                VFS_FCHMOD => {
                    handle_fchmod(&raw const msg, &raw mut reply, badge);
                }
                VFS_FCHOWN => {
                    handle_fchown(&raw const msg, &raw mut reply, badge);
                }
                VFS_CLIENT_EXIT => {
                    handle_client_exit(&raw const msg, &raw mut reply);
                    skip_reply = true; // one-way PM_EXIT cleanup notification
                }
                _ => {
                    reply.label = SALTY_INVALID_OPERATION;
                }
            }
        }
        } // close else block

        let err = if skip_reply {
            unsafe { ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge) }
        } else {
            unsafe { ipc::reply_recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw const reply, &raw mut msg, &raw mut badge) }
        };
        if err != 0 {
            { let mut lb = LineBuf::new(); lb.str(b"[VFS] reply_recv failed err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush(); }
            break;
        }
    }

    idle();
}

fn idle() -> ! {
    loop {
        salty::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
