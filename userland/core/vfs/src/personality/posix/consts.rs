// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX personality constants — `S_IF*` mode-format bits,
//! permission bits, `DT_*` dirent type bytes, `AT_*` openat
//! flags, and the small set of POSIX semantic limits the
//! synthetic in-memory filesystems consume directly.
//!
//! Personality-neutral code never imports from this module —
//! it is only loaded by the POSIX wire surface and by backends
//! that already encode their on-mount `mode` field in POSIX
//! shape (ramfs / tmpfs / devfs) for a one-line projection at
//! `getattr` reply time.
#![allow(dead_code)]

// =========================================================================
// S_IF* — inode mode type field
// =========================================================================

pub(crate) const S_IFMT_L: u32 = 0o170000;
pub(crate) const S_IFSOCK_L: u32 = 0o140000;
pub(crate) const S_IFLNK_L: u32 = 0o120000;
pub(crate) const S_IFREG_L: u32 = 0o100000;
pub(crate) const S_IFBLK_L: u32 = 0o060000;
pub(crate) const S_IFDIR_L: u32 = 0o040000;
pub(crate) const S_IFCHR_L: u32 = 0o020000;
pub(crate) const S_IFIFO_L: u32 = 0o010000;

// =========================================================================
// Mode permission bits
// =========================================================================

pub(crate) const S_ISUID: u32 = 0o4000;
pub(crate) const S_ISGID: u32 = 0o2000;
pub(crate) const S_ISVTX: u32 = 0o1000;

pub(crate) const S_IRWXU: u32 = 0o0700;
pub(crate) const S_IRUSR: u32 = 0o0400;
pub(crate) const S_IWUSR: u32 = 0o0200;
pub(crate) const S_IXUSR: u32 = 0o0100;

pub(crate) const S_IRWXG: u32 = 0o0070;
pub(crate) const S_IRGRP: u32 = 0o0040;
pub(crate) const S_IWGRP: u32 = 0o0020;
pub(crate) const S_IXGRP: u32 = 0o0010;

pub(crate) const S_IRWXO: u32 = 0o0007;
pub(crate) const S_IROTH: u32 = 0o0004;
pub(crate) const S_IWOTH: u32 = 0o0002;
pub(crate) const S_IXOTH: u32 = 0o0001;

// =========================================================================
// DT_* — dirent type byte (POSIX `d_type`)
// =========================================================================

pub(crate) const DT_UNKNOWN: u8 = 0;
pub(crate) const DT_FIFO: u8 = 1;
pub(crate) const DT_CHR: u8 = 2;
pub(crate) const DT_DIR: u8 = 4;
pub(crate) const DT_BLK: u8 = 6;
pub(crate) const DT_REG: u8 = 8;
pub(crate) const DT_LNK: u8 = 10;
pub(crate) const DT_SOCK: u8 = 12;

// =========================================================================
// AT_* — *at() syscall flags
// =========================================================================

pub(crate) const AT_FDCWD_VAL: i32 = -100;
pub(crate) const AT_SYMLINK_NOFOLLOW_VAL: i32 = 0x100;
pub(crate) const AT_REMOVEDIR_VAL: i32 = 0x200;
pub(crate) const AT_SYMLINK_FOLLOW_VAL: i32 = 0x400;
pub(crate) const AT_EMPTY_PATH_VAL: i32 = 0x1000;

// =========================================================================
// Pool sizing the synthetic filesystems consume
// =========================================================================

pub(crate) const MAX_SHM_PAGES: usize = 64;

// =========================================================================
// Mode → vtype byte projection
// =========================================================================

/// Map POSIX mode bits to the personality-neutral vtype byte used
/// by `Vnode.kind` / `Dirent.dtype`. Mode values that do not match
/// any known type bucket return `VT_BAD` so the caller can detect
/// malformed records.
#[inline]
pub(crate) const fn mode_to_vtype(mode: u32) -> u8 {
    match mode & S_IFMT_L {
        S_IFREG_L => crate::core::vnode::VT_REG,
        S_IFDIR_L => crate::core::vnode::VT_DIR,
        S_IFLNK_L => crate::core::vnode::VT_LNK,
        S_IFIFO_L => crate::core::vnode::VT_FIFO,
        S_IFCHR_L => crate::core::vnode::VT_CHR,
        S_IFBLK_L => crate::core::vnode::VT_BLK,
        S_IFSOCK_L => crate::core::vnode::VT_SOCK,
        _ => crate::core::vnode::VT_BAD,
    }
}

/// Inverse projection — vtype byte to the POSIX mode-format bits
/// (only the high `S_IFMT_L` slice; permission bits stay 0).
#[inline]
pub(crate) const fn vtype_to_mode(vtype: u8) -> u32 {
    use crate::core::vnode::{VT_BLK, VT_CHR, VT_DIR, VT_FIFO, VT_LNK, VT_REG, VT_SOCK};
    if vtype == VT_REG {
        S_IFREG_L
    } else if vtype == VT_DIR {
        S_IFDIR_L
    } else if vtype == VT_LNK {
        S_IFLNK_L
    } else if vtype == VT_FIFO {
        S_IFIFO_L
    } else if vtype == VT_CHR {
        S_IFCHR_L
    } else if vtype == VT_BLK {
        S_IFBLK_L
    } else if vtype == VT_SOCK {
        S_IFSOCK_L
    } else {
        0
    }
}

/// Map a vtype byte to the POSIX `d_type` byte for dirent emission.
#[inline]
pub(crate) const fn vtype_to_dtype(vtype: u8) -> u8 {
    use crate::core::vnode::{VT_BLK, VT_CHR, VT_DIR, VT_FIFO, VT_LNK, VT_REG, VT_SOCK};
    if vtype == VT_REG {
        DT_REG
    } else if vtype == VT_DIR {
        DT_DIR
    } else if vtype == VT_LNK {
        DT_LNK
    } else if vtype == VT_FIFO {
        DT_FIFO
    } else if vtype == VT_CHR {
        DT_CHR
    } else if vtype == VT_BLK {
        DT_BLK
    } else if vtype == VT_SOCK {
        DT_SOCK
    } else {
        DT_UNKNOWN
    }
}

// =========================================================================
// O_* — open() flag bits
// =========================================================================

pub(crate) const O_RDONLY: u32 = 0o00000000;
pub(crate) const O_WRONLY: u32 = 0o00000001;
pub(crate) const O_RDWR: u32 = 0o00000002;
pub(crate) const O_ACCMODE: u32 = 0o00000003;
pub(crate) const O_CREAT: u32 = 0o00000100;
pub(crate) const O_EXCL: u32 = 0o00000200;
pub(crate) const O_NOCTTY: u32 = 0o00000400;
pub(crate) const O_TRUNC: u32 = 0o00001000;
pub(crate) const O_APPEND: u32 = 0o00002000;
pub(crate) const O_NONBLOCK: u32 = 0o00004000;
pub(crate) const O_DSYNC: u32 = 0o00010000;
pub(crate) const O_DIRECT: u32 = 0o00040000;
pub(crate) const O_LARGEFILE: u32 = 0o00100000;
pub(crate) const O_DIRECTORY: u32 = 0o00200000;
pub(crate) const O_NOFOLLOW: u32 = 0o00400000;
pub(crate) const O_NOATIME: u32 = 0o01000000;
pub(crate) const O_CLOEXEC: u32 = 0o02000000;
pub(crate) const O_SYNC: u32 = 0o04010000;
pub(crate) const O_PATH: u32 = 0o010000000;
pub(crate) const O_TMPFILE: u32 = 0o020200000;

// =========================================================================
// FD_* — fd-table flag bits projected onto the personality-neutral
//         `slot_flags` byte the fd-table carries per slot.
//
// `POSIX_FD_CLOEXEC` and `WIN32_HANDLE_FLAG_INHERIT` (in
// `personality::win32::consts`) deliberately occupy the same bit
// position with inverted polarity — the fd-table itself stores the
// raw byte without interpretation, and each personality projects
// it onto its own ABI surface. POSIX semantics: bit set ⇒ exec
// closes; bit clear ⇒ exec inherits. Win32 semantics: bit clear
// ⇒ child inherits; bit set ⇒ child does not inherit. That
// makes `POSIX_FD_CLOEXEC` and `WIN32_HANDLE_FLAG_INHERIT == 0`
// the same on-disk bit, so a Win32 process inheriting an fd from
// its POSIX parent (and vice versa, once the multi-personality
// fork path is wired) sees the matching ABI semantics with no
// translation.
// =========================================================================

pub(crate) const POSIX_FD_CLOEXEC: u8 = crate::server::open_object::FD_FLAG_CLOEXEC;

// =========================================================================
// SEEK_* — lseek() whence values
// =========================================================================

pub(crate) const SEEK_SET: i32 = 0;
pub(crate) const SEEK_CUR: i32 = 1;
pub(crate) const SEEK_END: i32 = 2;
pub(crate) const SEEK_DATA: i32 = 3;
pub(crate) const SEEK_HOLE: i32 = 4;

// =========================================================================
// MAP_* — mmap() flags
// =========================================================================

pub(crate) const MAP_SHARED: u32 = 0x01;
pub(crate) const MAP_PRIVATE: u32 = 0x02;
pub(crate) const MAP_SHARED_VALIDATE: u32 = 0x03;
pub(crate) const MAP_TYPE: u32 = 0x0F;
pub(crate) const MAP_FIXED: u32 = 0x10;
pub(crate) const MAP_ANONYMOUS: u32 = 0x20;
pub(crate) const MAP_GROWSDOWN: u32 = 0x0100;
pub(crate) const MAP_DENYWRITE: u32 = 0x0800;
pub(crate) const MAP_EXECUTABLE: u32 = 0x1000;
pub(crate) const MAP_LOCKED: u32 = 0x2000;
pub(crate) const MAP_NORESERVE: u32 = 0x4000;
pub(crate) const MAP_POPULATE: u32 = 0x8000;
pub(crate) const MAP_NONBLOCK: u32 = 0x10000;
pub(crate) const MAP_STACK: u32 = 0x20000;
pub(crate) const MAP_HUGETLB: u32 = 0x40000;
pub(crate) const MAP_FIXED_NOREPLACE: u32 = 0x100000;

// =========================================================================
// PROT_* — mmap()/mprotect() page-protection bits
// =========================================================================

pub(crate) const PROT_NONE: u32 = 0x0;
pub(crate) const PROT_READ: u32 = 0x1;
pub(crate) const PROT_WRITE: u32 = 0x2;
pub(crate) const PROT_EXEC: u32 = 0x4;
pub(crate) const PROT_GROWSDOWN: u32 = 0x0100_0000;
pub(crate) const PROT_GROWSUP: u32 = 0x0200_0000;

// =========================================================================
// SCM_* — sendmsg() ancillary message types (cmsg_type within the
//         SOL_SOCKET cmsg_level)
// =========================================================================

pub(crate) const SCM_RIGHTS: i32 = 0x01;
pub(crate) const SCM_CREDENTIALS: i32 = 0x02;
pub(crate) const SCM_TIMESTAMP: i32 = 29;

// =========================================================================
// MSG_* — sendmsg() / recvmsg() flag bits
// =========================================================================

pub(crate) const MSG_OOB: i32 = 0x0001;
pub(crate) const MSG_PEEK: i32 = 0x0002;
pub(crate) const MSG_DONTROUTE: i32 = 0x0004;
pub(crate) const MSG_CTRUNC: i32 = 0x0008;
pub(crate) const MSG_TRUNC: i32 = 0x0020;
pub(crate) const MSG_DONTWAIT: i32 = 0x0040;
pub(crate) const MSG_EOR: i32 = 0x0080;
pub(crate) const MSG_WAITALL: i32 = 0x0100;
pub(crate) const MSG_NOSIGNAL: i32 = 0x4000;
pub(crate) const MSG_CMSG_CLOEXEC: i32 = 0x4000_0000;
