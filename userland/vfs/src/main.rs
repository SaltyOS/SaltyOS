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
use salty::types::*;

// ======================================================================
// Cap layout (VFS-specific — different from salty::consts well-known slots)
// ======================================================================

const CAP_SERVER_EP: u64 = 3;
const VFS_CAP_CONSOLE_EP: u64 = 4;
const VFS_CAP_NAMESERV_EP: u64 = 8;
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

// File type constants
const FTYPE_NONE: u8 = 0;
const FTYPE_CHAR_DEVICE: u8 = 1;
const FTYPE_REGULAR: u8 = 2;
const FTYPE_DIRECTORY: u8 = 3;

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

// Device types
const DEV_CONSOLE: u8 = 0;
const DEV_NULL: u8 = 1;
const DEV_ZERO: u8 = 2;

// Limits
const MAX_INODES: usize = 128;
const MAX_DIRENTS: usize = 32;
const MAX_WRITABLE: usize = 32;
const WRITABLE_SIZE: usize = 8192;
const MAX_CLIENTS: usize = 16;
const MAX_FDS: usize = 32;
const MAX_PATH_LEN: usize = 64;
const MAX_NAME_LEN: usize = 32;

// FD types
const FD_TYPE_NONE: u8 = 0;
const FD_TYPE_DEVICE: u8 = 1;
const FD_TYPE_FILE: u8 = 2;
const FD_TYPE_DIR: u8 = 3;

// Root inode
const ROOT_INO: u32 = 1;

const INITRD_VADDR: u64 = 0x0000_0000_0100_0000;

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
        }
    }
}

#[repr(C)]
struct ClientState {
    badge: u64,
    active: u8,
    fds: [FdEntry; MAX_FDS],
}

impl ClientState {
    const fn zeroed() -> Self {
        ClientState {
            badge: 0,
            active: 0,
            fds: [FdEntry::zeroed(); MAX_FDS],
        }
    }
}

// ======================================================================
// Global state
// ======================================================================

static mut INODES: [RamfsInode; MAX_INODES] = {
    const ZERO: RamfsInode = RamfsInode::zeroed();
    [ZERO; MAX_INODES]
};
static mut NEXT_INO: u32 = 1;

static mut WRITABLE_POOL: [[u8; WRITABLE_SIZE]; MAX_WRITABLE] =
    [[0; WRITABLE_SIZE]; MAX_WRITABLE];
static mut WRITABLE_USED: [u8; MAX_WRITABLE] = [0; MAX_WRITABLE];

static mut CLIENTS: [ClientState; MAX_CLIENTS] = {
    const ZERO: ClientState = ClientState::zeroed();
    [ZERO; MAX_CLIENTS]
};

// ======================================================================
// Helper functions
// ======================================================================

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn hex(v: u64) {
    serial::serial_hex(v);
}

fn putc(c: u8) {
    serial::serial_putc(c);
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
        for i in 0..MAX_INODES {
            if INODES[i].active != 0 && INODES[i].ino == ino {
                return &raw mut INODES[i];
            }
        }
        core::ptr::null_mut()
    }
}

unsafe fn alloc_inode() -> *mut RamfsInode {
    unsafe {
        for i in 0..MAX_INODES {
            if INODES[i].active == 0 {
                let n = &raw mut INODES[i];
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
        for i in 0..MAX_WRITABLE {
            if WRITABLE_USED[i] == 0 {
                WRITABLE_USED[i] = 1;
                for j in 0..WRITABLE_SIZE {
                    WRITABLE_POOL[i][j] = 0;
                }
                return WRITABLE_POOL[i].as_mut_ptr();
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

// ======================================================================
// Initialization
// ======================================================================

unsafe fn init_ramfs() {
    unsafe {
        for i in 0..MAX_INODES {
            INODES[i].active = 0;
        }
        for i in 0..MAX_WRITABLE {
            WRITABLE_USED[i] = 0;
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
        let initrd_size = cpio::cpio_archive_size(initrd, 1024 * 1024);

        puts(b"[VFS] Initrd size: ");
        hex(initrd_size as u64);
        puts(b" bytes\n");

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

            puts(b"[VFS] initrd: ");
            for i in 0..entry.name_len {
                putc(*entry.name.add(i));
            }
            puts(b" (");
            hex(entry.data_len as u64);
            puts(b")\n");
        }

        puts(b"[VFS] Mounted ");
        hex(file_count as u64);
        puts(b" initrd files\n");
    }
}

// ======================================================================
// Client management
// ======================================================================

unsafe fn get_client(badge: u64) -> *mut ClientState {
    unsafe {
        for i in 0..MAX_CLIENTS {
            if CLIENTS[i].active != 0 && CLIENTS[i].badge == badge {
                return &raw mut CLIENTS[i];
            }
        }
        for i in 0..MAX_CLIENTS {
            if CLIENTS[i].active == 0 {
                CLIENTS[i].badge = badge;
                CLIENTS[i].active = 1;
                for j in 0..MAX_FDS {
                    CLIENTS[i].fds[j].active = 0;
                }
                return &raw mut CLIENTS[i];
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
                puts(b"[VFS] OPEN: not found '");
                for i in 0..path_len as usize {
                    putc(path[i]);
                }
                puts(b"'\n");
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

        for fd in 0..MAX_FDS {
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
        if cli.is_null() || fd < 0 || fd >= MAX_FDS as i32 || (*cli).fds[fd as usize].active == 0 {
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
        if cli.is_null() || fd < 0 || fd >= MAX_FDS as i32 || (*cli).fds[fd as usize].active == 0 {
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
        if cli.is_null() || fd < 0 || fd >= MAX_FDS as i32 || (*cli).fds[fd as usize].active == 0 {
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
        if cli.is_null() || fd < 0 || fd >= MAX_FDS as i32 || (*cli).fds[fd as usize].active == 0 {
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
        if cli.is_null() || fd < 0 || fd >= MAX_FDS as i32 || (*cli).fds[fd as usize].active == 0 {
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

        for fd in 0..MAX_FDS {
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
            || fd >= MAX_FDS as i32
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
// Entry point
// ======================================================================

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    puts(b"[VFS] SaltyOS VFS server starting\n");

    let err = salty::invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
    if err != 0 {
        puts(b"[VFS] FAIL: set IPC buffer err=");
        hex(err as u64);
        puts(b"\n");
        idle();
    }
    unsafe {
        ipc::ipc_context_init(ipc_ctx(), IPC_BUF_VADDR as *mut IpcBuffer);
    }

    puts(b"[VFS] IPC buffer ready\n");

    unsafe {
        init_ramfs();
    }

    puts(b"[VFS] Filesystem ready\n");

    // Register with name server
    if VFS_CAP_NAMESERV_EP != 0 {
        let mut reg_msg = SaltyMsg::zeroed();
        let mut reg_reply = SaltyMsg::zeroed();
        reg_msg.label = 1; // NS_REGISTER
        reg_msg.regs[0] = 3; // length of "vfs"
        reg_msg.length = 1 + (3 + 7) / 8;
        let ns_dst = &raw mut reg_msg.regs[1] as *mut u8;
        unsafe {
            *ns_dst = b'v';
            *ns_dst.add(1) = b'f';
            *ns_dst.add(2) = b's';
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

    // Initial recv
    let mut msg = SaltyMsg::zeroed();
    let mut badge: u64 = 0;

    let err = unsafe { ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge) };
    if err != 0 {
        puts(b"[VFS] initial recv failed\n");
        idle();
    }

    // Server loop
    loop {
        let mut reply = SaltyMsg::zeroed();

        unsafe {
            match msg.label {
                VFS_OPEN => handle_open(&raw const msg, &raw mut reply, badge),
                VFS_READ => handle_read(&raw const msg, &raw mut reply, badge),
                VFS_WRITE => handle_write(&raw const msg, &raw mut reply, badge),
                VFS_CLOSE => handle_close(&raw const msg, &raw mut reply, badge),
                VFS_STAT => handle_stat(&raw const msg, &raw mut reply),
                VFS_LSEEK => handle_lseek(&raw const msg, &raw mut reply, badge),
                VFS_FSTAT => handle_fstat(&raw const msg, &raw mut reply, badge),
                VFS_ACCESS => handle_access(&raw const msg, &raw mut reply),
                VFS_UNLINK => handle_unlink(&raw const msg, &raw mut reply),
                VFS_RENAME => handle_rename(&raw const msg, &raw mut reply),
                VFS_MKDIR => handle_mkdir(&raw const msg, &raw mut reply),
                VFS_RMDIR => handle_rmdir(&raw const msg, &raw mut reply),
                VFS_OPENDIR => handle_opendir(&raw const msg, &raw mut reply, badge),
                VFS_READDIR => handle_readdir(&raw const msg, &raw mut reply, badge),
                VFS_LSTAT => handle_stat(&raw const msg, &raw mut reply), // no symlinks
                _ => {
                    puts(b"[VFS] unknown label=");
                    hex(msg.label);
                    puts(b"\n");
                    reply.label = SALTY_INVALID_OPERATION;
                }
            }
        }

        let err = unsafe {
            ipc::reply_recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw const reply, &raw mut msg, &raw mut badge)
        };
        if err != 0 {
            puts(b"[VFS] reply_recv failed err=");
            hex(err as u64);
            puts(b"\n");
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
