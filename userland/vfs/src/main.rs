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

const CAP_SERVER_EP: u64 = 3;
const VFS_CAP_CONSOLE_EP: u64 = 4;
const VFS_CAP_NAMESERV_EP: u64 = 8;
const VFS_CAP_FB_UNTYPED: u64 = 30;
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

// Device types
const DEV_CONSOLE: u8 = 0;
const DEV_NULL: u8 = 1;
const DEV_ZERO: u8 = 2;
const DEV_FB0: u8 = 3;

// Limits
const MAX_INODES: usize = 128;
const MAX_DIRENTS: usize = 32;
const MAX_WRITABLE: usize = 32;
const WRITABLE_SIZE: usize = 8192;
const MAX_CLIENTS: usize = 16;
const MAX_FDS: usize = 32;
const MAX_PATH_LEN: usize = 64;
const MAX_NAME_LEN: usize = 32;
const LOWMEM_TOTAL_BYTES: u64 = 8 * 1024 * 1024;
const MIDMEM_TOTAL_BYTES: u64 = 16 * 1024 * 1024;

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

// Socket/poll/shm limits
const MAX_SOCKETS: usize = 32;
const SOCK_BUF_SIZE: usize = 4096;
const MAX_POLL_WAITERS: usize = 16;
const MAX_SHM_PAGES: usize = 64;
const MAX_PENDING_CONN: usize = 4;

// Cap slot ranges for deferred reply
const CAP_REPLY_BASE: u64 = 32;

// Root inode
const ROOT_INO: u32 = 1;

const INITRD_VADDR: u64 = 0x0000_0000_0100_0000;
static mut LIMIT_INODES: usize = MAX_INODES;
static mut LIMIT_WRITABLE: usize = MAX_WRITABLE;
static mut LIMIT_CLIENTS: usize = MAX_CLIENTS;
static mut LIMIT_FDS: usize = MAX_FDS;
static mut LIMIT_SOCKETS: usize = MAX_SOCKETS;
static mut LIMIT_POLL_WAITERS: usize = MAX_POLL_WAITERS;
static mut LIMIT_EPOLL_INSTANCES: usize = MAX_EPOLL_INSTANCES;
static mut LIMIT_EPOLL_ENTRIES: usize = MAX_EPOLL_ENTRIES;
static mut LIMIT_SHM_OBJECTS: usize = MAX_SHM_OBJECTS;
static mut LIMIT_SHM_PAGES: usize = MAX_SHM_PAGES;
static mut LIMIT_PIPES: usize = MAX_PIPES;

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

fn read_boot_info_usable_bytes() -> u64 {
    unsafe {
        let page = BOOTINFO_VADDR as *const u64;
        let magic = core::ptr::read_volatile(page);
        if magic != BOOTINFO_MAGIC {
            return 0;
        }
        core::ptr::read_volatile(page.add(7))
    }
}

#[inline]
fn scale_limit(cap: usize, low: usize, mid: usize, usable_bytes: u64) -> usize {
    if usable_bytes == 0 {
        return cap;
    }
    if usable_bytes <= LOWMEM_TOTAL_BYTES {
        if low < 1 {
            1
        } else {
            low
        }
    } else if usable_bytes <= MIDMEM_TOTAL_BYTES {
        if mid < 1 {
            1
        } else if mid > cap {
            cap
        } else {
            mid
        }
    } else {
        cap
    }
}

unsafe fn init_runtime_limits() {
    unsafe {
        let usable = read_boot_info_usable_bytes();
        // Lowmem still mounts all initrd entries as inodes, so keep enough
        // headroom for runtime-created paths (/tmp, /dev/shm, test files).
        LIMIT_INODES = scale_limit(MAX_INODES, 48, 64, usable);
        LIMIT_WRITABLE = scale_limit(MAX_WRITABLE, 2, 6, usable);
        // Fork-heavy test workloads need multiple transient client badges.
        LIMIT_CLIENTS = scale_limit(MAX_CLIENTS, 10, 12, usable);
        LIMIT_FDS = scale_limit(MAX_FDS, 16, 24, usable);
        LIMIT_SOCKETS = scale_limit(MAX_SOCKETS, 4, 6, usable);
        LIMIT_POLL_WAITERS = scale_limit(MAX_POLL_WAITERS, 4, 6, usable);
        LIMIT_EPOLL_INSTANCES = scale_limit(MAX_EPOLL_INSTANCES, 2, 3, usable);
        LIMIT_EPOLL_ENTRIES = scale_limit(MAX_EPOLL_ENTRIES, 4, 6, usable);
        LIMIT_SHM_OBJECTS = scale_limit(MAX_SHM_OBJECTS, 2, 3, usable);
        LIMIT_SHM_PAGES = scale_limit(MAX_SHM_PAGES, 8, 12, usable);
        LIMIT_PIPES = scale_limit(MAX_PIPES, 4, 6, usable);

        // Keep dependent limits coherent.
        if LIMIT_EPOLL_ENTRIES > LIMIT_FDS {
            LIMIT_EPOLL_ENTRIES = LIMIT_FDS;
        }

        let mut lb = LineBuf::new();
        lb.str(b"[VFS] Runtime limits: inodes=");
        lb.hex(LIMIT_INODES as u64);
        lb.str(b" clients=");
        lb.hex(LIMIT_CLIENTS as u64);
        lb.str(b" fds=");
        lb.hex(LIMIT_FDS as u64);
        lb.str(b" sockets=");
        lb.hex(LIMIT_SOCKETS as u64);
        lb.str(b" shm_objs=");
        lb.hex(LIMIT_SHM_OBJECTS as u64);
        lb.str(b" shm_pages=");
        lb.hex(LIMIT_SHM_PAGES as u64);
        lb.str(b"\n");
        lb.flush();
    }
}

#[inline]
fn max_inodes() -> usize { unsafe { LIMIT_INODES } }
#[inline]
fn max_writable() -> usize { unsafe { LIMIT_WRITABLE } }
#[inline]
fn max_clients() -> usize { unsafe { LIMIT_CLIENTS } }
#[inline]
fn max_fds() -> usize { unsafe { LIMIT_FDS } }
#[inline]
fn max_sockets() -> usize { unsafe { LIMIT_SOCKETS } }
#[inline]
fn max_poll_waiters() -> usize { unsafe { LIMIT_POLL_WAITERS } }
#[inline]
fn max_epoll_instances() -> usize { unsafe { LIMIT_EPOLL_INSTANCES } }
#[inline]
fn max_epoll_entries() -> usize { unsafe { LIMIT_EPOLL_ENTRIES } }
#[inline]
fn max_shm_objects() -> usize { unsafe { LIMIT_SHM_OBJECTS } }
#[inline]
fn max_shm_pages() -> usize { unsafe { LIMIT_SHM_PAGES } }
#[inline]
fn max_pipes() -> usize { unsafe { LIMIT_PIPES } }

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
    dirents: [RamfsDirent; MAX_DIRENTS],
    ro_data: *const u8,
    rw_data: *mut u8,
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
            dirents: [RamfsDirent::zeroed(); MAX_DIRENTS],
            ro_data: core::ptr::null(),
            rw_data: core::ptr::null_mut(),
        }
    }
}

unsafe impl Sync for RamfsInode {}

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
    fds: [FdEntry; MAX_FDS],
    cwd: [u8; 128],
    fd_flags: [u8; MAX_FDS],
}

impl ClientState {
    const fn zeroed() -> Self {
        ClientState {
            badge: 0,
            active: 0,
            fds: [FdEntry::zeroed(); MAX_FDS],
            cwd: [0; 128],
            fd_flags: [0; MAX_FDS],
        }
    }
}

// ======================================================================
// Global state
// ======================================================================

static mut INODES_PTR: *mut RamfsInode = core::ptr::null_mut();
static mut NEXT_INO: u32 = 1;

static mut WRITABLE_POOL_PTR: *mut [u8; WRITABLE_SIZE] = core::ptr::null_mut();
static mut WRITABLE_USED_PTR: *mut u8 = core::ptr::null_mut();

static mut CLIENTS_PTR: *mut ClientState = core::ptr::null_mut();

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
    pending: [PendingConn; MAX_PENDING_CONN],
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
            pending: [PendingConn::zeroed(); MAX_PENDING_CONN],
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

macro_rules! POLL_WAITERS {
    () => {
        unsafe { core::slice::from_raw_parts_mut(POLL_WAITERS_PTR, max_poll_waiters()) }
    };
}

// ======================================================================
// Epoll data structures
// ======================================================================

const MAX_EPOLL_INSTANCES: usize = 8;
const MAX_EPOLL_ENTRIES: usize = 16;

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
    entries: [EpollEntry; MAX_EPOLL_ENTRIES],
}

impl EpollInstance {
    const fn zeroed() -> Self {
        EpollInstance {
            active: 0,
            owner_badge: 0,
            entries: {
                const ZERO: EpollEntry = EpollEntry::zeroed();
                [ZERO; MAX_EPOLL_ENTRIES]
            },
        }
    }
}

static mut EPOLLS_PTR: *mut EpollInstance = core::ptr::null_mut();

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
    frame_slots: [u64; MAX_SHM_PAGES],
}

impl ShmData {
    const fn zeroed() -> Self {
        ShmData { active: 0, num_pages: 0, frame_slots: [0; MAX_SHM_PAGES] }
    }
}

unsafe impl Sync for ShmData {}

const MAX_SHM_OBJECTS: usize = 8;
static mut SHM_DATA_PTR: *mut ShmData = core::ptr::null_mut();

macro_rules! SHM_DATA {
    () => {
        unsafe { core::slice::from_raw_parts_mut(SHM_DATA_PTR, max_shm_objects()) }
    };
}

// ======================================================================
// Pipe data structures
// ======================================================================

const PIPE_BUF_SIZE: usize = 4096;
const MAX_PIPES: usize = 16;
const FD_TYPE_PIPE: u8 = 7;
const FD_TYPE_EPOLL: u8 = 8;
const MAX_PIPE_WAITERS: usize = 4;

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
    recv_waiters: [PipeReadWaiter; MAX_PIPE_WAITERS],
    recv_waiter_count: u8,
    write_waiters: [PipeWriteWaiter; MAX_PIPE_WAITERS],
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
            recv_waiters: [PipeReadWaiter::zeroed(); MAX_PIPE_WAITERS],
            recv_waiter_count: 0,
            write_waiters: [PipeWriteWaiter::zeroed(); MAX_PIPE_WAITERS],
            write_waiter_count: 0,
        }
    }
}

unsafe impl Sync for PipeState {}

static mut PIPES_PTR: *mut PipeState = core::ptr::null_mut();
static mut NEXT_PIPE_ID: u32 = 1;

macro_rules! PIPES {
    () => {
        unsafe { core::slice::from_raw_parts_mut(PIPES_PTR, max_pipes()) }
    };
}

// Reply slot counter for deferred replies
static mut NEXT_REPLY_SLOT: u64 = CAP_REPLY_BASE;

// Dynamic SHM frame cap base — set at startup from __salty_next_frame_slot
// to avoid collision with rtld-loaded library frame caps
static mut VFS_SHM_CAP_BASE: u64 = 512;
const VFS_UNTYPED_FALLBACK_COUNT: u64 = 8;
const VFS_STATE_ARENA_VADDR_DEFAULT: u64 = 0x0000_0000_0500_0000;

static mut VFS_STATE_ARENA_BASE: *mut u8 = core::ptr::null_mut();
static mut VFS_STATE_ARENA_SIZE: usize = 0;
static mut VFS_STATE_ARENA_OFF: usize = 0;
static mut VFS_NEXT_FRAME_SLOT: u64 = 0;

unsafe fn retype_frame_from_any_untyped(frame_slot: u64) -> u64 {
    let mut err = salty::invoke::untyped_retype(CAP_UNTYPED, OBJ_FRAME, 0, frame_slot);
    if err == 0 {
        return 0;
    }

    let mut best_err = err as u64;
    for ut in CAP_UNTYPED_START..(CAP_UNTYPED_START + VFS_UNTYPED_FALLBACK_COUNT) {
        err = salty::invoke::untyped_retype(ut, OBJ_FRAME, 0, frame_slot);
        if err == 0 {
            return 0;
        }
        if err != SALTY_INVALID_CAPABILITY as i32
            && err != SALTY_INVALID_OPERATION as i32
            && err != SALTY_NOT_FOUND as i32
        {
            best_err = err as u64;
        }
    }

    best_err
}

#[inline]
fn align_up_usize(value: usize, align: usize) -> usize {
    if align <= 1 {
        value
    } else {
        (value + align - 1) & !(align - 1)
    }
}

#[inline]
fn layout_add(total: usize, bytes: usize, align: usize) -> Option<usize> {
    let aligned = align_up_usize(total, align);
    aligned.checked_add(bytes)
}

unsafe fn vfs_map_state_arena(total_bytes: usize) -> i32 {
    if total_bytes == 0 {
        return 0;
    }

    let pages = (total_bytes + 4095) / 4096;
    let arena_bytes = pages * 4096;
    let base = VFS_STATE_ARENA_VADDR_DEFAULT;

    unsafe {
        for pg in 0..pages {
            let slot = VFS_NEXT_FRAME_SLOT;
            VFS_NEXT_FRAME_SLOT = VFS_NEXT_FRAME_SLOT.wrapping_add(1);

            let rerr = retype_frame_from_any_untyped(slot);
            if rerr != 0 {
                let mut lb = LineBuf::new();
                lb.str(b"[VFS] state arena frame retype failed err=");
                lb.hex(rerr);
                lb.str(b"\n");
                lb.flush();
                return rerr as i32;
            }

            let vaddr = base + (pg as u64) * 4096;
            let merr = salty::invoke::vspace_map(
                CAP_SELF_VSPACE,
                slot,
                vaddr,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if merr != 0 {
                let mut lb = LineBuf::new();
                lb.str(b"[VFS] state arena map failed err=");
                lb.hex(merr as u64);
                lb.str(b"\n");
                lb.flush();
                return merr;
            }
        }

        core::ptr::write_bytes(base as *mut u8, 0, arena_bytes);
        VFS_STATE_ARENA_BASE = base as *mut u8;
        VFS_STATE_ARENA_SIZE = arena_bytes;
        VFS_STATE_ARENA_OFF = 0;
    }

    0
}

unsafe fn vfs_arena_alloc(bytes: usize, align: usize) -> *mut u8 {
    if bytes == 0 {
        return core::ptr::null_mut();
    }

    unsafe {
        let start = align_up_usize(VFS_STATE_ARENA_OFF, align);
        let Some(end) = start.checked_add(bytes) else {
            return core::ptr::null_mut();
        };
        if end > VFS_STATE_ARENA_SIZE {
            return core::ptr::null_mut();
        }
        VFS_STATE_ARENA_OFF = end;
        VFS_STATE_ARENA_BASE.add(start)
    }
}

unsafe fn init_dynamic_state_storage() -> i32 {
    unsafe {
        let inodes_bytes = core::mem::size_of::<RamfsInode>()
            .checked_mul(max_inodes())
            .unwrap_or(0);
        let writable_pool_bytes = core::mem::size_of::<[u8; WRITABLE_SIZE]>()
            .checked_mul(max_writable())
            .unwrap_or(0);
        let writable_used_bytes = core::mem::size_of::<u8>()
            .checked_mul(max_writable())
            .unwrap_or(0);
        let clients_bytes = core::mem::size_of::<ClientState>()
            .checked_mul(max_clients())
            .unwrap_or(0);
        let sockets_bytes = core::mem::size_of::<SocketState>()
            .checked_mul(max_sockets())
            .unwrap_or(0);
        let poll_waiters_bytes = core::mem::size_of::<PollWaiter>()
            .checked_mul(max_poll_waiters())
            .unwrap_or(0);
        let epolls_bytes = core::mem::size_of::<EpollInstance>()
            .checked_mul(max_epoll_instances())
            .unwrap_or(0);
        let shm_bytes = core::mem::size_of::<ShmData>()
            .checked_mul(max_shm_objects())
            .unwrap_or(0);
        let pipes_bytes = core::mem::size_of::<PipeState>()
            .checked_mul(max_pipes())
            .unwrap_or(0);

        if inodes_bytes == 0
            || writable_pool_bytes == 0
            || clients_bytes == 0
            || sockets_bytes == 0
            || pipes_bytes == 0
        {
            return SALTY_OUT_OF_MEMORY as i32;
        }

        let mut total = 0usize;
        total = match layout_add(total, inodes_bytes, core::mem::align_of::<RamfsInode>()) {
            Some(v) => v,
            None => return SALTY_OUT_OF_MEMORY as i32,
        };
        total = match layout_add(total, writable_pool_bytes, core::mem::align_of::<[u8; WRITABLE_SIZE]>()) {
            Some(v) => v,
            None => return SALTY_OUT_OF_MEMORY as i32,
        };
        total = match layout_add(total, writable_used_bytes, core::mem::align_of::<u8>()) {
            Some(v) => v,
            None => return SALTY_OUT_OF_MEMORY as i32,
        };
        total = match layout_add(total, clients_bytes, core::mem::align_of::<ClientState>()) {
            Some(v) => v,
            None => return SALTY_OUT_OF_MEMORY as i32,
        };
        total = match layout_add(total, sockets_bytes, core::mem::align_of::<SocketState>()) {
            Some(v) => v,
            None => return SALTY_OUT_OF_MEMORY as i32,
        };
        total = match layout_add(total, poll_waiters_bytes, core::mem::align_of::<PollWaiter>()) {
            Some(v) => v,
            None => return SALTY_OUT_OF_MEMORY as i32,
        };
        total = match layout_add(total, epolls_bytes, core::mem::align_of::<EpollInstance>()) {
            Some(v) => v,
            None => return SALTY_OUT_OF_MEMORY as i32,
        };
        total = match layout_add(total, shm_bytes, core::mem::align_of::<ShmData>()) {
            Some(v) => v,
            None => return SALTY_OUT_OF_MEMORY as i32,
        };
        total = match layout_add(total, pipes_bytes, core::mem::align_of::<PipeState>()) {
            Some(v) => v,
            None => return SALTY_OUT_OF_MEMORY as i32,
        };

        VFS_NEXT_FRAME_SLOT = salty::__salty_next_frame_slot;
        let err = vfs_map_state_arena(total);
        if err != 0 {
            return err;
        }

        INODES_PTR = vfs_arena_alloc(inodes_bytes, core::mem::align_of::<RamfsInode>()) as *mut RamfsInode;
        WRITABLE_POOL_PTR = vfs_arena_alloc(writable_pool_bytes, core::mem::align_of::<[u8; WRITABLE_SIZE]>())
            as *mut [u8; WRITABLE_SIZE];
        WRITABLE_USED_PTR = vfs_arena_alloc(writable_used_bytes, core::mem::align_of::<u8>());
        CLIENTS_PTR = vfs_arena_alloc(clients_bytes, core::mem::align_of::<ClientState>()) as *mut ClientState;
        SOCKETS_PTR = vfs_arena_alloc(sockets_bytes, core::mem::align_of::<SocketState>()) as *mut SocketState;
        POLL_WAITERS_PTR = vfs_arena_alloc(poll_waiters_bytes, core::mem::align_of::<PollWaiter>()) as *mut PollWaiter;
        EPOLLS_PTR = vfs_arena_alloc(epolls_bytes, core::mem::align_of::<EpollInstance>()) as *mut EpollInstance;
        SHM_DATA_PTR = vfs_arena_alloc(shm_bytes, core::mem::align_of::<ShmData>()) as *mut ShmData;
        PIPES_PTR = vfs_arena_alloc(pipes_bytes, core::mem::align_of::<PipeState>()) as *mut PipeState;

        if INODES_PTR.is_null()
            || WRITABLE_POOL_PTR.is_null()
            || WRITABLE_USED_PTR.is_null()
            || CLIENTS_PTR.is_null()
            || SOCKETS_PTR.is_null()
            || POLL_WAITERS_PTR.is_null()
            || EPOLLS_PTR.is_null()
            || SHM_DATA_PTR.is_null()
            || PIPES_PTR.is_null()
        {
            return SALTY_OUT_OF_MEMORY as i32;
        }

        VFS_SHM_CAP_BASE = VFS_NEXT_FRAME_SLOT;
        salty::__salty_next_frame_slot = VFS_NEXT_FRAME_SLOT;

        let mut lb = LineBuf::new();
        lb.str(b"[VFS] state arena: bytes=");
        lb.hex(total as u64);
        lb.str(b" pages=");
        lb.hex(((total + 4095) / 4096) as u64);
        lb.str(b" shm_cap_base=");
        lb.hex(VFS_SHM_CAP_BASE);
        lb.str(b" base=");
        lb.hex(VFS_STATE_ARENA_BASE as u64);
        lb.str(b"\n");
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
                for j in 0..MAX_DIRENTS {
                    (*n).dirents[j].active = 0;
                }
                return n;
            }
        }
        core::ptr::null_mut()
    }
}

unsafe fn alloc_writable() -> *mut u8 {
    unsafe {
        for i in 0..max_writable() {
            if WRITABLE_USED!()[i] == 0 {
                WRITABLE_USED!()[i] = 1;
                for j in 0..WRITABLE_SIZE {
                    WRITABLE_POOL!()[i][j] = 0;
                }
                return WRITABLE_POOL!()[i].as_mut_ptr();
            }
        }
        core::ptr::null_mut()
    }
}

unsafe fn dir_add_entry(dir: *mut RamfsInode, name: *const u8, name_len: u8, child_ino: u32) -> i32 {
    unsafe {
        for i in 0..MAX_DIRENTS {
            if (*dir).dirents[i].active == 0 {
                (*dir).dirents[i].active = 1;
                (*dir).dirents[i].ino = child_ino;
                (*dir).dirents[i].name_len = name_len;
                let n = if (name_len as usize) < MAX_NAME_LEN {
                    name_len as usize
                } else {
                    MAX_NAME_LEN
                };
                for j in 0..n {
                    (*dir).dirents[i].name[j] = *name.add(j);
                }
                return 0;
            }
        }
        -1
    }
}

unsafe fn dir_find_entry(dir: *mut RamfsInode, name: *const u8, name_len: u8) -> *mut RamfsDirent {
    unsafe {
        for i in 0..MAX_DIRENTS {
            if (*dir).dirents[i].active != 0
                && str_equal_raw(
                    (*dir).dirents[i].name.as_ptr(),
                    (*dir).dirents[i].name_len as usize,
                    name,
                    name_len as usize,
                )
            {
                return &raw mut (*dir).dirents[i];
            }
        }
        core::ptr::null_mut()
    }
}

unsafe fn dir_remove_entry(dir: *mut RamfsInode, name: *const u8, name_len: u8) -> i32 {
    unsafe {
        for i in 0..MAX_DIRENTS {
            if (*dir).dirents[i].active != 0
                && str_equal_raw(
                    (*dir).dirents[i].name.as_ptr(),
                    (*dir).dirents[i].name_len as usize,
                    name,
                    name_len as usize,
                )
            {
                (*dir).dirents[i].active = 0;
                return 0;
            }
        }
        -1
    }
}

// ======================================================================
// Path resolution
// ======================================================================

unsafe fn resolve_path(path: *const u8, path_len: u8) -> *mut RamfsInode {
    unsafe {
        if path_len == 0 {
            return core::ptr::null_mut();
        }

        let mut current = inode_by_ino(ROOT_INO);
        if current.is_null() {
            return core::ptr::null_mut();
        }

        // Root itself
        if path_len == 1 && *path == b'/' {
            return current;
        }

        let mut pos: usize = 0;
        if *path == b'/' {
            pos = 1;
        }

        let plen = path_len as usize;
        while pos < plen {
            if (*current).ftype != FTYPE_DIRECTORY {
                return core::ptr::null_mut();
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
            if (*current).ftype != FTYPE_DIRECTORY {
                return core::ptr::null_mut();
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
        if dirfd < 0 || dirfd >= max_fds() as i32 || (*cli).fds[dirfd as usize].active == 0 {
            return 0;
        }
        (*cli).fds[dirfd as usize].inode
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
            if entry.name_len >= MAX_NAME_LEN {
                continue;
            }

            let file_inode = alloc_inode();
            if file_inode.is_null() {
                break;
            }

            (*file_inode).readonly = 1;
            if entry.ino != 0 {
                (*file_inode).ino = entry.ino;
            }
            if entry.mode != 0 {
                (*file_inode).mode = entry.mode;
            } else {
                (*file_inode).mode = S_IFREG_L | 0o444;
            }
            if entry.nlink != 0 {
                (*file_inode).nlink = entry.nlink;
            } else {
                (*file_inode).nlink = 1;
            }
            (*file_inode).mtime = entry.mtime;
            (*file_inode).size = entry.data_len as u64;
            (*file_inode).ro_data = entry.data;
            (*file_inode).parent_ino = (*initrd_dir).ino;

            if (entry.mode & S_IFMT_L) == S_IFDIR_L {
                (*file_inode).ftype = FTYPE_DIRECTORY;
            } else {
                (*file_inode).ftype = FTYPE_REGULAR;
            }

            dir_add_entry(
                initrd_dir,
                entry.name,
                entry.name_len as u8,
                (*file_inode).ino,
            );
            file_count += 1;

            { let mut lb = LineBuf::new(); lb.str(b"[VFS] initrd: "); lb.bytes(core::slice::from_raw_parts(entry.name, entry.name_len)); lb.str(b" ("); lb.hex(entry.data_len as u64); lb.str(b")\n"); lb.flush(); }
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
                for j in 0..max_fds() {
                    CLIENTS!()[i].fds[j].active = 0;
                    CLIENTS!()[i].fd_flags[j] = 0;
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
        core::ptr::null_mut()
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
// Request handlers
// ======================================================================

unsafe fn handle_open(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let flags = (*msg).regs[1] as u32;
        let path_len = extract_path(msg, 2, path.as_mut_ptr());

        if path_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let mut inode = resolve_path(path.as_ptr(), path_len);

        if inode.is_null() {
            if (flags & O_CREAT) == 0 {
                (*reply).label = SALTY_NOT_FOUND;
                return;
            }

            let mut child_name: *const u8 = core::ptr::null();
            let mut child_len: u8 = 0;
            let parent = resolve_parent(path.as_ptr(), path_len, &mut child_name, &mut child_len);
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
                { let mut lb = LineBuf::new(); lb.str(b"[VFS] OPEN: not found '"); lb.bytes(&path[..path_len as usize]); lb.str(b"'\n"); lb.flush(); }
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
                (*inode).size = 0;
            }
        }

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        for fd in 0..max_fds() {
            if (*cli).fds[fd].active == 0 {
                (*cli).fds[fd].active = 1;
                (*cli).fds[fd].inode = (*inode).ino;
                (*cli).fds[fd].offset = 0;
                (*cli).fds[fd].dir_cursor = 0;
                (*cli).fds[fd].flags = flags;

                if (*inode).ftype == FTYPE_CHAR_DEVICE {
                    (*cli).fds[fd].fd_type = FD_TYPE_DEVICE;
                    (*cli).fds[fd].dev_type = (*inode).dev_type;
                } else if (*inode).ftype == FTYPE_DIRECTORY {
                    (*cli).fds[fd].fd_type = FD_TYPE_DIR;
                } else if (*inode).ftype == FTYPE_FIFO {
                    // FIFO: create pipe fd using the pipe_id stored in inode.size
                    let pipe_id = (*inode).size as u32;
                    let pipe = find_pipe(pipe_id);
                    if pipe.is_null() {
                        (*cli).fds[fd].active = 0;
                        (*reply).label = SALTY_INVALID_OPERATION;
                        return;
                    }
                    (*cli).fds[fd].fd_type = FD_TYPE_PIPE;
                    (*cli).fds[fd].sock_id = pipe_id;
                    if flags_allow_write(flags) {
                        (*cli).fds[fd].flags = O_WRONLY;
                        (*pipe).write_refcount += 1;
                    } else {
                        (*cli).fds[fd].flags = 0; // O_RDONLY
                        (*pipe).read_refcount += 1;
                    }
                } else {
                    (*cli).fds[fd].fd_type = FD_TYPE_FILE;
                    if (flags & O_APPEND) != 0 {
                        (*cli).fds[fd].offset = (*inode).size;
                    }
                }

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
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32 || (*cli).fds[fd as usize].active == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        if count > 152 {
            count = 152;
        }

        if !flags_allow_read((*cli).fds[fd as usize].flags) {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let fde = &mut (*cli).fds[fd as usize];

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
                    let c = creply.regs[0];
                    if c == u64::MAX {
                        (*reply).label = SALTY_OK;
                        (*reply).length = 1;
                        (*reply).regs[0] = 0;
                    } else {
                        (*reply).label = SALTY_OK;
                        (*reply).length = 2;
                        (*reply).regs[0] = 1;
                        let data = &raw mut (*reply).regs[1] as *mut u8;
                        *data = c as u8;
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
                DEV_FB0 => {
                    (*reply).label = SALTY_INVALID_OPERATION;
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

                let src: *const u8;
                if !(*inode).ro_data.is_null() {
                    src = (*inode).ro_data.add(offset as usize);
                } else if !(*inode).rw_data.is_null() {
                    src = (*inode).rw_data.add(offset as usize);
                } else {
                    (*reply).label = SALTY_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = 0;
                    return;
                }

                (*reply).label = SALTY_OK;
                (*reply).length = 1 + (count + 7) / 8;
                (*reply).regs[0] = count;
                let dst = &raw mut (*reply).regs[1] as *mut u8;
                for i in 0..count as usize {
                    *dst.add(i) = *src.add(i);
                }

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
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32 || (*cli).fds[fd as usize].active == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        if count > 144 {
            count = 144;
        }

        if !flags_allow_write((*cli).fds[fd as usize].flags) {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let fde = &mut (*cli).fds[fd as usize];

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
                DEV_NULL | DEV_ZERO => {
                    (*reply).label = SALTY_OK;
                    (*reply).length = 1;
                    (*reply).regs[0] = count;
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

                if offset >= WRITABLE_SIZE as u64 {
                    count = 0;
                } else if offset + count > WRITABLE_SIZE as u64 {
                    count = WRITABLE_SIZE as u64 - offset;
                }

                let src = &(*msg).regs[2] as *const u64 as *const u8;
                for i in 0..count as usize {
                    *(*inode).rw_data.add(offset as usize + i) = *src.add(i);
                }

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
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32 || (*cli).fds[fd as usize].active == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        (*cli).fds[fd as usize].active = 0;
        (*reply).label = SALTY_OK;
    }
}

unsafe fn handle_lseek(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let offset = (*msg).regs[1] as i64;
        let whence = (*msg).regs[2] as i32;

        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32 || (*cli).fds[fd as usize].active == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        if (*cli).fds[fd as usize].fd_type != FD_TYPE_FILE {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        let inode = inode_by_ino((*cli).fds[fd as usize].inode);
        if inode.is_null() {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let new_offset: i64 = match whence {
            0 => offset, // SEEK_SET
            1 => (*cli).fds[fd as usize].offset as i64 + offset, // SEEK_CUR
            2 => (*inode).size as i64 + offset, // SEEK_END
            _ => {
                (*reply).label = SALTY_INVALID_ARGUMENT;
                return;
            }
        };

        if new_offset < 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        (*cli).fds[fd as usize].offset = new_offset as u64;
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
        (*reply).regs[7] = (*inode).ftype as u64;
    }
}

unsafe fn handle_fstat(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32 || (*cli).fds[fd as usize].active == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let inode = inode_by_ino((*cli).fds[fd as usize].inode);
        if inode.is_null() {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }
        fill_stat_reply(reply, inode);
    }
}

unsafe fn handle_stat(msg: *const SaltyMsg, reply: *mut SaltyMsg) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 0, path.as_mut_ptr());
        let inode = resolve_path(path.as_ptr(), path_len);
        if inode.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }
        fill_stat_reply(reply, inode);
    }
}

unsafe fn handle_access(msg: *const SaltyMsg, reply: *mut SaltyMsg) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 1, path.as_mut_ptr());
        let inode = resolve_path(path.as_ptr(), path_len);
        if inode.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }
        (*reply).label = SALTY_OK;
    }
}

unsafe fn handle_unlink(msg: *const SaltyMsg, reply: *mut SaltyMsg) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 0, path.as_mut_ptr());

        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent(path.as_ptr(), path_len, &mut child_name, &mut child_len);
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
        (*inode).active = 0;
        (*reply).label = SALTY_OK;
    }
}

unsafe fn handle_rename(msg: *const SaltyMsg, reply: *mut SaltyMsg) {
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
        let raw = &(*msg).regs[2] as *const u64 as *const u8;
        for i in 0..old_len as usize {
            old_path[i] = *raw.add(i);
        }
        let raw2 = raw.add(((old_len as usize) + 7) / 8 * 8);
        for i in 0..new_len as usize {
            new_path[i] = *raw2.add(i);
        }

        // Resolve old parent + child
        let mut old_child: *const u8 = core::ptr::null();
        let mut old_child_len: u8 = 0;
        let old_parent =
            resolve_parent(old_path.as_ptr(), old_len, &mut old_child, &mut old_child_len);
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
            resolve_parent(new_path.as_ptr(), new_len, &mut new_child, &mut new_child_len);
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
                (*old_inode).active = 0;
            }
            (*existing).active = 0;
        }

        dir_add_entry(new_parent, new_child, new_child_len, ino);
        (*reply).label = SALTY_OK;
    }
}

unsafe fn handle_mkdir(msg: *const SaltyMsg, reply: *mut SaltyMsg) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 1, path.as_mut_ptr());

        let existing = resolve_path(path.as_ptr(), path_len);
        if !existing.is_null() {
            (*reply).label = SALTY_ALREADY_EXISTS;
            return;
        }

        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent(path.as_ptr(), path_len, &mut child_name, &mut child_len);
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

unsafe fn handle_mkfifo(msg: *const SaltyMsg, reply: *mut SaltyMsg) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 1, path.as_mut_ptr());

        let existing = resolve_path(path.as_ptr(), path_len);
        if !existing.is_null() {
            (*reply).label = SALTY_ALREADY_EXISTS;
            return;
        }

        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent(path.as_ptr(), path_len, &mut child_name, &mut child_len);
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

unsafe fn handle_rmdir(msg: *const SaltyMsg, reply: *mut SaltyMsg) {
    unsafe {
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 0, path.as_mut_ptr());

        let inode = resolve_path(path.as_ptr(), path_len);
        if inode.is_null() || (*inode).ftype != FTYPE_DIRECTORY {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        if (*inode).readonly != 0 {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        // Check directory is empty
        for i in 0..MAX_DIRENTS {
            if (*inode).dirents[i].active != 0 {
                (*reply).label = SALTY_INVALID_OPERATION;
                return;
            }
        }

        // Remove from parent
        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent(path.as_ptr(), path_len, &mut child_name, &mut child_len);
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
                (*inode).size = 0;
            }
        }

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        for fd in 0..max_fds() {
            if (*cli).fds[fd].active == 0 {
                (*cli).fds[fd].active = 1;
                (*cli).fds[fd].inode = (*inode).ino;
                (*cli).fds[fd].offset = 0;
                (*cli).fds[fd].dir_cursor = 0;
                (*cli).fds[fd].flags = flags;

                if (*inode).ftype == FTYPE_CHAR_DEVICE {
                    (*cli).fds[fd].fd_type = FD_TYPE_DEVICE;
                    (*cli).fds[fd].dev_type = (*inode).dev_type;
                } else if (*inode).ftype == FTYPE_DIRECTORY {
                    (*cli).fds[fd].fd_type = FD_TYPE_DIR;
                } else if (*inode).ftype == FTYPE_FIFO {
                    let pipe_id = (*inode).size as u32;
                    let pipe = find_pipe(pipe_id);
                    if pipe.is_null() {
                        (*cli).fds[fd].active = 0;
                        (*reply).label = SALTY_INVALID_OPERATION;
                        return;
                    }
                    (*cli).fds[fd].fd_type = FD_TYPE_PIPE;
                    (*cli).fds[fd].sock_id = pipe_id;
                    if flags_allow_write(flags) {
                        (*cli).fds[fd].flags = O_WRONLY;
                        (*pipe).write_refcount += 1;
                    } else {
                        (*cli).fds[fd].flags = 0;
                        (*pipe).read_refcount += 1;
                    }
                } else {
                    (*cli).fds[fd].fd_type = FD_TYPE_FILE;
                    if (flags & O_APPEND) != 0 {
                        (*cli).fds[fd].offset = (*inode).size;
                    }
                }

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
            if cli.is_null() || dirfd >= max_fds() as i32
                || (*cli).fds[dirfd as usize].active == 0
            {
                (*reply).label = SALTY_INVALID_ARGUMENT;
                return;
            }
            inode_by_ino((*cli).fds[dirfd as usize].inode)
        } else {
            resolve_path_from(start_ino, path.as_ptr(), path_len)
        };

        if inode.is_null() {
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
            for i in 0..MAX_DIRENTS {
                if (*inode).dirents[i].active != 0 {
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
            (*inode).active = 0;
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
                (*old_inode).active = 0;
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
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32
            || (*cli).fds[fd as usize].active == 0
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
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32
            || (*cli).fds[fd as usize].active == 0
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
            if cli.is_null() || dirfd >= max_fds() as i32
                || (*cli).fds[dirfd as usize].active == 0
            {
                (*reply).label = SALTY_INVALID_ARGUMENT;
                return;
            }
            inode_by_ino((*cli).fds[dirfd as usize].inode)
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
        let path_len = extract_path(msg, 0, path.as_mut_ptr());

        let inode = resolve_path(path.as_ptr(), path_len);
        if inode.is_null() || (*inode).ftype != FTYPE_DIRECTORY {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }

        let cli = get_client(badge);
        if cli.is_null() {
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        for fd in 0..max_fds() {
            if (*cli).fds[fd].active == 0 {
                (*cli).fds[fd].active = 1;
                (*cli).fds[fd].fd_type = FD_TYPE_DIR;
                (*cli).fds[fd].inode = (*inode).ino;
                (*cli).fds[fd].offset = 0;
                (*cli).fds[fd].dir_cursor = 0;
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
            || fd >= max_fds() as i32
            || (*cli).fds[fd as usize].active == 0
            || (*cli).fds[fd as usize].fd_type != FD_TYPE_DIR
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let dir = inode_by_ino((*cli).fds[fd as usize].inode);
        if dir.is_null() {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let cursor = (*cli).fds[fd as usize].dir_cursor;
        for i in (cursor as usize)..MAX_DIRENTS {
            if (*dir).dirents[i].active != 0 {
                let child = inode_by_ino((*dir).dirents[i].ino);
                let d_type: u8 = if !child.is_null() {
                    match (*child).ftype {
                        FTYPE_REGULAR => 8,     // DT_REG
                        FTYPE_DIRECTORY => 4,   // DT_DIR
                        FTYPE_CHAR_DEVICE => 2, // DT_CHR
                        _ => 0,
                    }
                } else {
                    0
                };

                let name_len = (*dir).dirents[i].name_len;
                (*reply).label = SALTY_OK;
                (*reply).length = 5 + ((name_len as u64 + 7) / 8);
                (*reply).regs[0] = name_len as u64;
                (*reply).regs[1] = 0; // reserved
                (*reply).regs[2] = (*dir).dirents[i].ino as u64;
                (*reply).regs[3] = d_type as u64;

                for j in 4..20 {
                    (*reply).regs[j] = 0;
                }
                let dst = &raw mut (*reply).regs[4] as *mut u8;
                for j in 0..name_len as usize {
                    *dst.add(j) = (*dir).dirents[i].name[j];
                }

                (*cli).fds[fd as usize].dir_cursor = (i + 1) as u32;
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
                for j in 0..MAX_PENDING_CONN { (*s).pending[j].active = 0; }
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
        core::ptr::null_mut()
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
        if NEXT_REPLY_SLOT > CAP_REPLY_BASE + 64 {
            NEXT_REPLY_SLOT = CAP_REPLY_BASE;
        }
        slot
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
                return p;
            }
        }
        core::ptr::null_mut()
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
        if count >= MAX_PIPE_WAITERS { return false; }
        (*pipe).recv_waiters[count].reply_slot = slot;
        (*pipe).recv_waiters[count].badge = badge;
        (*pipe).recv_waiters[count].requested_len = req_len;
        (*pipe).recv_waiter_count = (count + 1) as u8;
        true
    }
}

/// Pop the first read waiter from the pipe's FIFO queue.
unsafe fn pipe_pop_recv_waiter(pipe: *mut PipeState) -> Option<PipeReadWaiter> {
    unsafe {
        let count = (*pipe).recv_waiter_count as usize;
        if count == 0 { return None; }
        let waiter = (*pipe).recv_waiters[0];
        // Shift remaining waiters down
        for i in 1..count {
            (*pipe).recv_waiters[i - 1] = (*pipe).recv_waiters[i];
        }
        (*pipe).recv_waiters[count - 1] = PipeReadWaiter::zeroed();
        (*pipe).recv_waiter_count = (count - 1) as u8;
        Some(waiter)
    }
}

/// Push a write waiter onto the pipe's FIFO queue with saved data. Returns false if full.
unsafe fn pipe_push_write_waiter(pipe: *mut PipeState, slot: u64, badge: u64, src: *const u8, len: u16) -> bool {
    unsafe {
        let count = (*pipe).write_waiter_count as usize;
        if count >= MAX_PIPE_WAITERS { return false; }
        (*pipe).write_waiters[count].reply_slot = slot;
        (*pipe).write_waiters[count].badge = badge;
        (*pipe).write_waiters[count].data_len = len;
        let actual = if len > 144 { 144 } else { len };
        for i in 0..actual as usize {
            (*pipe).write_waiters[count].data[i] = *src.add(i);
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
        let waiter = (*pipe).write_waiters[0];
        // Shift remaining waiters down
        for i in 1..count {
            (*pipe).write_waiters[i - 1] = (*pipe).write_waiters[i];
        }
        (*pipe).write_waiters[count - 1] = PipeWriteWaiter::zeroed();
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
                if pfd < 0 || pfd >= max_fds() as i32 { continue; }
                let fde = &(*cli).fds[pfd as usize];
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
        for i in 0..max_fds() {
            if (*cli).fds[i].active == 0 {
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
        for i in 0..max_fds() {
            if (*cli).fds[i].active == 0 && i as i32 != read_fd {
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
        (*cli).fds[read_fd as usize].active = 1;
        (*cli).fds[read_fd as usize].fd_type = FD_TYPE_PIPE;
        (*cli).fds[read_fd as usize].sock_id = (*pipe).pipe_id; // reuse sock_id for pipe_id
        (*cli).fds[read_fd as usize].flags = if flags & 0x0800 != 0 { 0x0800u32 } else { 0 }; // O_NONBLOCK on read end
        (*cli).fds[read_fd as usize].offset = 0;

        // Set up write-end fd
        (*cli).fds[write_fd as usize].active = 1;
        (*cli).fds[write_fd as usize].fd_type = FD_TYPE_PIPE;
        (*cli).fds[write_fd as usize].sock_id = (*pipe).pipe_id;
        (*cli).fds[write_fd as usize].flags = O_WRONLY | (if flags & 0x0800 != 0 { 0x0800u32 } else { 0 }); // O_WRONLY + O_NONBLOCK
        (*cli).fds[write_fd as usize].offset = 0;

        // O_CLOEXEC
        if flags & 0x80000 != 0 {
            (*cli).fd_flags[read_fd as usize] = 1;  // FD_CLOEXEC
            (*cli).fd_flags[write_fd as usize] = 1;
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
        if cli.is_null() || oldfd < 0 || oldfd >= max_fds() as i32
            || (*cli).fds[oldfd as usize].active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Find lowest free fd
        let mut newfd: i32 = -1;
        for i in 0..max_fds() {
            if (*cli).fds[i].active == 0 {
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
        if cli.is_null() || oldfd < 0 || oldfd >= max_fds() as i32
            || newfd < 0 || newfd >= max_fds() as i32
            || (*cli).fds[oldfd as usize].active == 0
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
        if (*cli).fds[newfd as usize].active != 0 {
            let fde = &raw mut (*cli).fds[newfd as usize];
            if (*fde).fd_type == FD_TYPE_SOCKET {
                close_socket(fde);
            } else if (*fde).fd_type == FD_TYPE_PIPE {
                close_pipe(fde);
            }
            (*cli).fds[newfd as usize].active = 0;
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
        if cli.is_null() || oldfd < 0 || oldfd >= max_fds() as i32
            || newfd < 0 || newfd >= max_fds() as i32
            || (*cli).fds[oldfd as usize].active == 0
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
        if (*cli).fds[newfd as usize].active != 0 {
            let fde = &raw mut (*cli).fds[newfd as usize];
            if (*fde).fd_type == FD_TYPE_SOCKET {
                close_socket(fde);
            } else if (*fde).fd_type == FD_TYPE_PIPE {
                close_pipe(fde);
            }
            (*cli).fds[newfd as usize].active = 0;
        }

        dup_fd_entry(cli, oldfd, newfd);

        // Apply flags (O_CLOEXEC = 0x80000)
        if flags & 0x80000 != 0 {
            (*cli).fd_flags[newfd as usize] = 1; // FD_CLOEXEC
        } else {
            (*cli).fd_flags[newfd as usize] = 0;
        }

        (*reply).label = SALTY_OK;
        (*reply).length = 1;
        (*reply).regs[0] = newfd as u64;
    }
}

/// Copy fd entry and increment refcounts as needed.
unsafe fn dup_fd_entry(cli: *mut ClientState, oldfd: i32, newfd: i32) {
    unsafe {
        (*cli).fds[newfd as usize] = (*cli).fds[oldfd as usize];
        let fde = &(*cli).fds[newfd as usize];
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

        // Copy all FDs from parent to child
        for i in 0..max_fds() {
            (*child).fds[i] = (*parent).fds[i];
            (*child).fd_flags[i] = (*parent).fd_flags[i];
            if (*child).fds[i].active == 0 { continue; }
            // Increment pipe refcounts
            if (*child).fds[i].fd_type == FD_TYPE_PIPE {
                let pipe = find_pipe((*child).fds[i].pipe_id());
                if !pipe.is_null() {
                    let is_read = ((*child).fds[i].flags & O_ACCMODE) == 0;
                    if is_read {
                        (*pipe).read_refcount += 1;
                    } else {
                        (*pipe).write_refcount += 1;
                    }
                }
            }
            // Increment socket refcounts
            if (*child).fds[i].fd_type == FD_TYPE_SOCKET {
                let sock = find_socket((*child).fds[i].sock_id);
                if !sock.is_null() {
                    (*sock).refcount += 1;
                }
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

// ======================================================================
// isatty / ioctl / fcntl / chdir / getcwd handlers
// ======================================================================

unsafe fn handle_isatty(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32
            || (*cli).fds[fd as usize].active == 0
        {
            (*reply).label = SALTY_OK;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }

        let is_tty = if (*cli).fds[fd as usize].fd_type == FD_TYPE_DEVICE
            && (*cli).fds[fd as usize].dev_type == DEV_CONSOLE
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

/// Forward tcgetattr to console server via CONSOLE_TCGETATTR IPC
unsafe fn handle_tcgetattr(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32
            || (*cli).fds[fd as usize].active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Only console device supports termios
        if (*cli).fds[fd as usize].fd_type != FD_TYPE_DEVICE
            || (*cli).fds[fd as usize].dev_type != DEV_CONSOLE
        {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

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

        // Pass through console's reply (flags + c_cc in regs[0..9])
        (*reply).label = SALTY_OK;
        (*reply).length = creply.length;
        for i in 0..creply.length as usize {
            (*reply).regs[i] = creply.regs[i];
        }
    }
}

/// Forward tcsetattr to console server via CONSOLE_TCSETATTR IPC
unsafe fn handle_tcsetattr(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32
            || (*cli).fds[fd as usize].active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Only console device supports termios
        if (*cli).fds[fd as usize].fd_type != FD_TYPE_DEVICE
            || (*cli).fds[fd as usize].dev_type != DEV_CONSOLE
        {
            (*reply).label = SALTY_INVALID_OPERATION;
            return;
        }

        // Forward to console server — regs[0]=fd, regs[1]=action, regs[2..11]=termios data
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
    }
}

/// Check readiness of a single fd for given events. Returns revents bitmask.
unsafe fn check_fd_readiness(cli: *const ClientState, fd: i32, events: u32) -> u32 {
    unsafe {
        if fd < 0 || fd >= max_fds() as i32 || (*cli).fds[fd as usize].active == 0 {
            return 0x020; // POLLNVAL
        }

        let fde = &(*cli).fds[fd as usize];
        let mut rev: u32 = 0;

        match fde.fd_type {
            FD_TYPE_FILE | FD_TYPE_DIR => {
                if events & 0x001 != 0 { rev |= 0x001; }
                if events & 0x004 != 0 { rev |= 0x004; }
            }
            FD_TYPE_DEVICE => {
                if events & 0x004 != 0 { rev |= 0x004; }
                if events & 0x001 != 0 { rev |= 0x001; }
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
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // Find free fd
        let mut fd: i32 = -1;
        for i in 0..max_fds() {
            if (*cli).fds[i].active == 0 {
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
        for j in 0..max_epoll_entries() {
            EPOLLS!()[epoll_idx as usize].entries[j].active = 0;
        }

        // Init fd entry
        (*cli).fds[fd as usize].active = 1;
        (*cli).fds[fd as usize].fd_type = FD_TYPE_EPOLL;
        (*cli).fds[fd as usize].sock_id = epoll_idx as u32; // reuse sock_id for epoll index
        (*cli).fds[fd as usize].inode = 0;
        (*cli).fds[fd as usize].offset = 0;
        (*cli).fds[fd as usize].flags = 0;

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
        if cli.is_null() || epfd < 0 || epfd >= max_fds() as i32
            || (*cli).fds[epfd as usize].active == 0
            || (*cli).fds[epfd as usize].fd_type != FD_TYPE_EPOLL
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let ep_idx = (*cli).fds[epfd as usize].sock_id as usize;
        if ep_idx >= max_epoll_instances() || EPOLLS!()[ep_idx].active == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Validate target fd
        if fd < 0 || fd >= max_fds() as i32 || (*cli).fds[fd as usize].active == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let ep = &mut EPOLLS!()[ep_idx];

        match op {
            1 => { // EPOLL_CTL_ADD
                // Check not already present
                for i in 0..max_epoll_entries() {
                    if ep.entries[i].active != 0 && ep.entries[i].fd == fd {
                        (*reply).label = SALTY_INVALID_ARGUMENT; // EEXIST
                        return;
                    }
                }
                // Find free slot
                let mut slot: i32 = -1;
                for i in 0..max_epoll_entries() {
                    if ep.entries[i].active == 0 {
                        slot = i as i32;
                        break;
                    }
                }
                if slot < 0 {
                    (*reply).label = SALTY_OUT_OF_MEMORY;
                    return;
                }
                ep.entries[slot as usize].active = 1;
                ep.entries[slot as usize].fd = fd;
                ep.entries[slot as usize].events = events;
                ep.entries[slot as usize].data = data;
            }
            2 => { // EPOLL_CTL_DEL
                let mut found = false;
                for i in 0..max_epoll_entries() {
                    if ep.entries[i].active != 0 && ep.entries[i].fd == fd {
                        ep.entries[i].active = 0;
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
                for i in 0..max_epoll_entries() {
                    if ep.entries[i].active != 0 && ep.entries[i].fd == fd {
                        ep.entries[i].events = events;
                        ep.entries[i].data = data;
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
        if cli.is_null() || epfd < 0 || epfd >= max_fds() as i32
            || (*cli).fds[epfd as usize].active == 0
            || (*cli).fds[epfd as usize].fd_type != FD_TYPE_EPOLL
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let ep_idx = (*cli).fds[epfd as usize].sock_id as usize;
        if ep_idx >= max_epoll_instances() || EPOLLS!()[ep_idx].active == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let ep = &EPOLLS!()[ep_idx];
        let cap = if max_events > 8 { 8 } else { max_events };
        let mut ready_count: usize = 0;

        // Check readiness for each entry in the interest list
        for i in 0..max_epoll_entries() {
            if ep.entries[i].active == 0 {
                continue;
            }
            if ready_count >= cap {
                break;
            }

            let rev = check_fd_readiness(cli, ep.entries[i].fd, ep.entries[i].events);
            if rev != 0 {
                // Pack: regs[1 + ready*2] = events, regs[2 + ready*2] = data
                (*reply).regs[1 + ready_count * 2] = rev as u64;
                (*reply).regs[2 + ready_count * 2] = ep.entries[i].data;
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
                for i in 0..max_epoll_entries() {
                    if ep.entries[i].active == 0 || n >= 8 {
                        continue;
                    }
                    POLL_WAITERS!()[w].fds[n as usize].0 = ep.entries[i].fd;
                    POLL_WAITERS!()[w].fds[n as usize].1 = ep.entries[i].events as u16;
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
        let _arg = (*msg).regs[2];

        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32
            || (*cli).fds[fd as usize].active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        if (*cli).fds[fd as usize].fd_type == FD_TYPE_DEVICE
            && (*cli).fds[fd as usize].dev_type == DEV_FB0
        {
            handle_ioctl_fb0(request, reply);
            return;
        }

        match request {
            // TIOCGPGRP: get foreground process group
            0x540F => {
                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0; // pgid 0 (single process group)
            }
            // TIOCSPGRP: set foreground process group (accept and ignore)
            0x5410 => {
                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
            }
            // TIOCGWINSZ: get terminal window size
            0x5413 => {
                (*reply).label = SALTY_OK;
                (*reply).length = 2;
                // Pack rows(16) | cols(16) into regs[0], xpixel(16) | ypixel(16) into regs[1]
                (*reply).regs[0] = (24u64 << 16) | 80u64; // rows=24, cols=80
                (*reply).regs[1] = 0; // xpixel=0, ypixel=0
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
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32
            || (*cli).fds[fd as usize].active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let fde = &(*cli).fds[fd as usize];

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
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32
            || (*cli).fds[fd as usize].active == 0
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
                while i < max_fds() {
                    if (*cli).fds[i].active == 0 {
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
                    (*cli).fd_flags[newfd as usize] = 1; // FD_CLOEXEC
                } else {
                    (*cli).fd_flags[newfd as usize] = 0;
                }

                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = newfd as u64;
            }
            // F_GETFD: get fd flags
            1 => {
                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = (*cli).fd_flags[fd as usize] as u64;
            }
            // F_SETFD: set fd flags
            2 => {
                (*cli).fd_flags[fd as usize] = arg as u8;
                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
            }
            // F_GETFL: get file status flags
            3 => {
                (*reply).label = SALTY_OK;
                (*reply).length = 1;
                (*reply).regs[0] = (*cli).fds[fd as usize].flags as u64;
            }
            // F_SETFL: set file status flags (only O_APPEND, O_NONBLOCK are changeable)
            4 => {
                let changeable = O_APPEND | 0x0800; // O_APPEND | O_NONBLOCK
                let preserved = (*cli).fds[fd as usize].flags & !changeable;
                (*cli).fds[fd as usize].flags = preserved | (arg as u32 & changeable);
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
        let path_len = extract_path(msg, 0, path.as_mut_ptr());
        if path_len == 0 {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Validate that path exists and is a directory
        let inode = resolve_path(path.as_ptr(), path_len);
        if inode.is_null() {
            (*reply).label = SALTY_NOT_FOUND;
            return;
        }
        if (*inode).ftype != FTYPE_DIRECTORY {
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
            (*cli).cwd[i] = path[i];
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

        // Pack cwd bytes into reply regs[1..] (up to 152 bytes)
        let copy_len = if cwd_len < 152 { cwd_len } else { 152 };
        let _ = max_size; // acknowledged but we always send the actual cwd
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

        for fd in 0..max_fds() {
            if (*cli).fds[fd].active == 0 {
                (*cli).fds[fd].active = 1;
                (*cli).fds[fd].fd_type = FD_TYPE_SOCKET;
                (*cli).fds[fd].sock_id = (*sock).sock_id;
                (*cli).fds[fd].offset = 0;
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
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32
            || (*cli).fds[fd as usize].active == 0
            || (*cli).fds[fd as usize].fd_type != FD_TYPE_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let sock = find_socket((*cli).fds[fd as usize].sock_id);
        if sock.is_null() || (*sock).state != SOCK_UNBOUND {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        // Extract path
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 1, path.as_mut_ptr());

        // Create a socket inode at this path
        let existing = resolve_path(path.as_ptr(), path_len);
        if !existing.is_null() {
            (*reply).label = SALTY_ALREADY_EXISTS;
            return false;
        }

        let mut child_name: *const u8 = core::ptr::null();
        let mut child_len: u8 = 0;
        let parent = resolve_parent(path.as_ptr(), path_len, &mut child_name, &mut child_len);
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
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32
            || (*cli).fds[fd as usize].active == 0
            || (*cli).fds[fd as usize].fd_type != FD_TYPE_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let sock = find_socket((*cli).fds[fd as usize].sock_id);
        if sock.is_null() || (*sock).state != SOCK_BOUND {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        (*sock).state = SOCK_LISTENING;
        (*sock).backlog = if backlog > MAX_PENDING_CONN as u8 { MAX_PENDING_CONN as u8 } else { backlog };
        (*reply).label = SALTY_OK;
        false
    }
}

unsafe fn handle_accept(msg: *const SaltyMsg, reply: *mut SaltyMsg, badge: u64) -> bool {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let cli = get_client(badge);
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32
            || (*cli).fds[fd as usize].active == 0
            || (*cli).fds[fd as usize].fd_type != FD_TYPE_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let listen_sock = find_socket((*cli).fds[fd as usize].sock_id);
        if listen_sock.is_null() || (*listen_sock).state != SOCK_LISTENING {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        // Check for pending connection
        for i in 0..MAX_PENDING_CONN {
            if (*listen_sock).pending[i].active != 0 {
                let pend = (*listen_sock).pending[i];
                (*listen_sock).pending[i].active = 0;
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
                for fdn in 0..max_fds() {
                    if (*cli).fds[fdn].active == 0 {
                        (*cli).fds[fdn].active = 1;
                        (*cli).fds[fdn].fd_type = FD_TYPE_SOCKET;
                        (*cli).fds[fdn].sock_id = (*srv_sock).sock_id;
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
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32
            || (*cli).fds[fd as usize].active == 0
            || (*cli).fds[fd as usize].fd_type != FD_TYPE_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let cli_sock = find_socket((*cli).fds[fd as usize].sock_id);
        if cli_sock.is_null() || (*cli_sock).state != SOCK_UNBOUND {
            (*reply).label = SALTY_INVALID_OPERATION;
            return false;
        }

        // Resolve path to find listening socket
        let mut path = [0u8; MAX_PATH_LEN];
        let path_len = extract_path(msg, 1, path.as_mut_ptr());
        let inode = resolve_path(path.as_ptr(), path_len);
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
                for fdn in 0..max_fds() {
                    if (*accepter_cli).fds[fdn].active == 0 {
                        (*accepter_cli).fds[fdn].active = 1;
                        (*accepter_cli).fds[fdn].fd_type = FD_TYPE_SOCKET;
                        (*accepter_cli).fds[fdn].sock_id = (*srv_sock).sock_id;
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

        for i in 0..MAX_PENDING_CONN {
            if (*listen_sock).pending[i].active == 0 {
                (*listen_sock).pending[i].active = 1;
                (*listen_sock).pending[i].client_badge = badge;
                (*listen_sock).pending[i].sock_id = (*cli_sock).sock_id;
                (*listen_sock).pending[i].reply_slot = slot;
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
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32
            || (*cli).fds[fd as usize].active == 0
            || (*cli).fds[fd as usize].fd_type != FD_TYPE_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let sock = find_socket((*cli).fds[fd as usize].sock_id);
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
        for fdn in 0..max_fds() {
            if (*cli).fds[fdn].active == 0 {
                if fd1 < 0 {
                    (*cli).fds[fdn].active = 1;
                    (*cli).fds[fdn].fd_type = FD_TYPE_SOCKET;
                    (*cli).fds[fdn].sock_id = (*s1).sock_id;
                    fd1 = fdn as i32;
                } else if fd2 < 0 {
                    (*cli).fds[fdn].active = 1;
                    (*cli).fds[fdn].fd_type = FD_TYPE_SOCKET;
                    (*cli).fds[fdn].sock_id = (*s2).sock_id;
                    fd2 = fdn as i32;
                    break;
                }
            }
        }

        if fd1 < 0 || fd2 < 0 {
            (*s1).active = 0;
            (*s2).active = 0;
            if fd1 >= 0 { (*cli).fds[fd1 as usize].active = 0; }
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
        for i in 0..MAX_PENDING_CONN {
            if (*sock).pending[i].active != 0 && (*sock).pending[i].reply_slot != 0 {
                let mut wake = SaltyMsg::zeroed();
                wake.label = SALTY_INVALID_OPERATION;
                ipc::send_ctx(ipc_ctx(), (*sock).pending[i].reply_slot, &raw const wake);
                (*sock).pending[i].active = 0;
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
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32
            || (*cli).fds[fd as usize].active == 0
            || (*cli).fds[fd as usize].fd_type != FD_TYPE_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let sock = find_socket((*cli).fds[fd as usize].sock_id);
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
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32
            || (*cli).fds[fd as usize].active == 0
            || (*cli).fds[fd as usize].fd_type != FD_TYPE_SOCKET
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let sock = find_socket((*cli).fds[fd as usize].sock_id);
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
                if src_cli.is_null() || src_fd < 0 || src_fd >= max_fds() as i32 { continue; }
                let src_fde = &(*src_cli).fds[src_fd as usize];
                if src_fde.active == 0 { continue; }

                // Duplicate fd into receiver's fd table
                let mut new_fd: i32 = -1;
                for fdn in 0..max_fds() {
                    if (*cli).fds[fdn].active == 0 {
                        (*cli).fds[fdn] = *src_fde;
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

            if pfd < 0 || pfd >= max_fds() as i32 || (*cli).fds[pfd as usize].active == 0 {
                revents_arr[i] = 0x020; // POLLNVAL
                ready_count += 1;
                continue;
            }

            let fde = &(*cli).fds[pfd as usize];
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
            // No free waiter slot — reply with error via saved cap
            let mut err_reply = SaltyMsg::zeroed();
            err_reply.label = SALTY_OUT_OF_MEMORY;
            ipc::send_ctx(ipc_ctx(), slot, &raw const err_reply);
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
            for fd in 0..max_fds() {
                if (*cli).fds[fd].active == 0 {
                    (*cli).fds[fd].active = 1;
                    (*cli).fds[fd].fd_type = FD_TYPE_SHM;
                    (*cli).fds[fd].inode = (*existing).ino;
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
            (*inode).active = 0;
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return false;
        }

        // Store SHM index in inode dev_type field (repurposed)
        (*inode).dev_type = shm_idx as u8;

        let cli = get_client(badge);
        if cli.is_null() {
            (*inode).active = 0;
            (*reply).label = SALTY_OUT_OF_MEMORY;
            return false;
        }

        for fd in 0..max_fds() {
            if (*cli).fds[fd].active == 0 {
                (*cli).fds[fd].active = 1;
                (*cli).fds[fd].fd_type = FD_TYPE_SHM;
                (*cli).fds[fd].inode = (*inode).ino;
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
        if cli.is_null() || fd < 0 || fd >= max_fds() as i32
            || (*cli).fds[fd as usize].active == 0
        {
            (*reply).label = SALTY_INVALID_ARGUMENT;
            return false;
        }

        let fde = &(*cli).fds[fd as usize];

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

            // Allocate frames
            let shm = &raw mut SHM_DATA!()[shm_idx];
            // Use high cap slots for SHM frames: 192+
            let frame_base: u64 = VFS_SHM_CAP_BASE + shm_idx as u64 * max_shm_pages() as u64;

            for i in (*shm).num_pages..num_pages {
                let slot = frame_base + i as u64;
                let err = retype_frame_from_any_untyped(slot);
                if err != 0 {
                    (*reply).label = err;
                    return false;
                }
                (*shm).frame_slots[i as usize] = slot;
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
        (*inode).size = length;
        (*reply).label = SALTY_OK;
        false
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

    unsafe {
        init_runtime_limits();
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
    loop {
        let mut reply = SaltyMsg::zeroed();
        let mut skip_reply = false;

        unsafe {
            match msg.label {
                VFS_OPEN => { handle_open(&raw const msg, &raw mut reply, badge); }
                VFS_READ => {
                    let fd = msg.regs[0] as i32;
                    let cli = get_client(badge);
                    if !cli.is_null() && fd >= 0 && fd < max_fds() as i32
                        && (*cli).fds[fd as usize].active != 0
                    {
                        match (*cli).fds[fd as usize].fd_type {
                            FD_TYPE_SOCKET => {
                                skip_reply = handle_socket_read(
                                    &raw mut (*cli).fds[fd as usize], &raw mut reply, badge);
                            }
                            FD_TYPE_PIPE => {
                                skip_reply = handle_pipe_read(
                                    &raw const msg, &raw mut (*cli).fds[fd as usize], &raw mut reply, badge);
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
                    if !cli.is_null() && fd >= 0 && fd < max_fds() as i32
                        && (*cli).fds[fd as usize].active != 0
                    {
                        match (*cli).fds[fd as usize].fd_type {
                            FD_TYPE_SOCKET => {
                                skip_reply = handle_socket_write(
                                    &raw const msg, &raw mut (*cli).fds[fd as usize], &raw mut reply);
                            }
                            FD_TYPE_PIPE => {
                                skip_reply = handle_pipe_write(
                                    &raw const msg, &raw mut (*cli).fds[fd as usize], &raw mut reply, badge);
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
                    if !cli.is_null() && fd >= 0 && fd < max_fds() as i32
                        && (*cli).fds[fd as usize].active != 0
                    {
                        match (*cli).fds[fd as usize].fd_type {
                            FD_TYPE_SOCKET => {
                                close_socket(&raw mut (*cli).fds[fd as usize]);
                            }
                            FD_TYPE_PIPE => {
                                close_pipe(&raw mut (*cli).fds[fd as usize]);
                            }
                            FD_TYPE_EPOLL => {
                                let ep_idx = (*cli).fds[fd as usize].sock_id as usize;
                                if ep_idx < max_epoll_instances() {
                                    EPOLLS!()[ep_idx].active = 0;
                                }
                            }
                            _ => {}
                        }
                    }
                    handle_close(&raw const msg, &raw mut reply, badge);
                }
                VFS_STAT => { handle_stat(&raw const msg, &raw mut reply); }
                VFS_LSEEK => { handle_lseek(&raw const msg, &raw mut reply, badge); }
                VFS_FSTAT => { handle_fstat(&raw const msg, &raw mut reply, badge); }
                VFS_ACCESS => { handle_access(&raw const msg, &raw mut reply); }
                VFS_UNLINK => { handle_unlink(&raw const msg, &raw mut reply); }
                VFS_RENAME => { handle_rename(&raw const msg, &raw mut reply); }
                VFS_MKDIR => { handle_mkdir(&raw const msg, &raw mut reply); }
                VFS_RMDIR => { handle_rmdir(&raw const msg, &raw mut reply); }
                VFS_OPENDIR => { handle_opendir(&raw const msg, &raw mut reply, badge); }
                VFS_READDIR => { handle_readdir(&raw const msg, &raw mut reply, badge); }
                VFS_LSTAT => { handle_stat(&raw const msg, &raw mut reply); }
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
                    handle_mkfifo(&raw const msg, &raw mut reply);
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
                VFS_LINKAT | VFS_SYMLINKAT | VFS_READLINKAT => {
                    // No hard links or symlinks — ENOSYS
                    reply.label = SALTY_INVALID_OPERATION;
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
                _ => {
                    { let mut lb = LineBuf::new(); lb.str(b"[VFS] unknown label="); lb.hex(msg.label); lb.str(b"\n"); lb.flush(); }
                    reply.label = SALTY_INVALID_OPERATION;
                }
            }
        }

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
