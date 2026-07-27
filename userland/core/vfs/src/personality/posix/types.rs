// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX personality wire-ABI structs.

// =========================================================================
// POSIX wire-ABI structs
//
// Linux x86_64 layouts. These are the byte shapes that POSIX
// callers (basaltc, future libc-compatible static binaries)
// expect across the vfs wire — `read(fd, &stat_buf, …)` / dirent
// entries returned in readdir SHM batches / sockaddr passed
// through bind / connect / sendmsg / recvmsg.
//
// Field order is fixed by ABI; do not reorder. New fields go at
// the end in unused padding only.
// =========================================================================

/// `struct timespec` — POSIX nanosecond timestamp pair.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// `struct timeval` — older microsecond timestamp pair, used by
/// utimes / select.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

/// `struct stat` — Linux x86_64 layout, 144 bytes. Returned by
/// fstat / fstatat / lstat / statx (statx has its own larger
/// shape).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub _pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atim: Timespec,
    pub st_mtim: Timespec,
    pub st_ctim: Timespec,
    pub _unused: [i64; 3],
}

/// `struct statvfs` — POSIX filesystem statistics, ~64 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Statvfs {
    pub f_bsize: u64,
    pub f_frsize: u64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_favail: u64,
    pub f_fsid: u64,
    pub f_flag: u64,
    pub f_namemax: u64,
}

/// Maximum POSIX filename length carried in `Dirent::d_name`. The
/// dirent's variable-length tail is sized so the whole record
/// fits inside `d_reclen`; emitters truncate and the kernel
/// guarantees `\0` termination on the wire.
pub(crate) const POSIX_NAME_MAX: usize = 255;

/// `struct dirent64` — Linux 64-bit dirent. Records carry the
/// inode, the cursor offset for the next call, the record length
/// (the variable-tail flag), the type byte, and a NUL-terminated
/// name. Wire layout is variable-length — this struct is the
/// fixed-prefix shape; emitters write `d_name` past the prefix.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct Dirent {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
    pub d_name: [u8; POSIX_NAME_MAX + 1],
}

impl Default for Dirent {
    fn default() -> Self {
        Self {
            d_ino: 0,
            d_off: 0,
            d_reclen: 0,
            d_type: 0,
            d_name: [0u8; POSIX_NAME_MAX + 1],
        }
    }
}

/// `struct pollfd` — passed by reference array to `poll(2)`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

/// Inline `pollfd` capacity carried in the VFS_POLL IPC register
/// form: regs[0..2] are header, every `pollfd` consumes three
/// words (`fd`, `events`, `revents`).
pub(crate) const POLLFD_INLINE_MAX: usize = 10;

/// `struct epoll_event` — Linux x86_64 layout, *packed* so the
/// 8-byte `data` lands on a 4-byte boundary. The size on the
/// wire is 12 bytes.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct EpollEvent {
    pub events: u32,
    /// User-supplied cookie returned on every fired event. Stored
    /// as a `u64` because the public ABI is a union of `int / void
    /// * / uint64_t`; vfs treats it opaquely.
    pub data: u64,
}

pub(crate) const EPOLL_MAX_INTERESTS: usize = 64;

#[derive(Clone, Copy)]
pub(crate) struct EpollInterest {
    pub(crate) target_obj_slot: u32,
    pub(crate) target_obj_epoch: u32,
    pub(crate) events_mask: u32,
    _pad: u32,
    pub(crate) user_data: u64,
}

impl EpollInterest {
    pub(crate) const fn zeroed() -> Self {
        Self {
            target_obj_slot: u32::MAX,
            target_obj_epoch: 0,
            events_mask: 0,
            _pad: 0,
            user_data: 0,
        }
    }
}

pub(crate) struct EpollInstance {
    pub(crate) active: u8,
    _pad0: u8,
    pub(crate) count: u16,
    _pad1: u32,
    pub(crate) entries: [EpollInterest; EPOLL_MAX_INTERESTS],
}

impl EpollInstance {
    pub(crate) const fn zeroed() -> Self {
        Self {
            active: 0,
            _pad0: 0,
            count: 0,
            _pad1: 0,
            entries: [const { EpollInterest::zeroed() }; EPOLL_MAX_INTERESTS],
        }
    }
}

/// `sigset_t` — POSIX signal mask. Linux layout is 1024 bits
/// (128 bytes); only the low 64 bits are meaningful in practice.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct Sigset {
    pub bits: [u64; 16],
}

impl Default for Sigset {
    fn default() -> Self {
        Self { bits: [0u64; 16] }
    }
}

// =========================================================================
// POSIX socket-address shapes
// =========================================================================

pub(crate) const AF_UNIX: u16 = 1;
pub(crate) const AF_INET: u16 = 2;
pub(crate) const AF_INET6: u16 = 10;

/// Generic sockaddr — header that every concrete sockaddr_* shape
/// shares. Used as the wire-erased view that `bind / connect /
/// accept / sendmsg / recvmsg` carry.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct Sockaddr {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}

/// Maximum UNIX-domain socket path length, including the trailing
/// NUL. Linux uses 108; the abstract namespace (leading `\0`) and
/// pathname namespace share the same buffer.
pub(crate) const SOCKADDR_UN_PATH_MAX: usize = 108;

/// `sockaddr_un` — AF_UNIX sockaddr.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct SockaddrUn {
    pub sun_family: u16,
    pub sun_path: [u8; SOCKADDR_UN_PATH_MAX],
}

/// `struct in_addr` — 32-bit IPv4 address, network byte order.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct InAddr {
    pub s_addr: u32,
}

/// `sockaddr_in` — AF_INET sockaddr.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SockaddrIn {
    pub sin_family: u16,
    /// Port in network byte order.
    pub sin_port: u16,
    pub sin_addr: InAddr,
    pub sin_zero: [u8; 8],
}

/// `struct in6_addr` — 128-bit IPv6 address.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct In6Addr {
    pub s6_addr: [u8; 16],
}

/// `sockaddr_in6` — AF_INET6 sockaddr.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SockaddrIn6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: In6Addr,
    pub sin6_scope_id: u32,
}

/// `sockaddr_storage` — POSIX-mandated catch-all sockaddr that is
/// large and aligned enough to hold any concrete sockaddr_*. 128
/// bytes on Linux.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct SockaddrStorage {
    pub ss_family: u16,
    pub _pad: [u8; 126],
}

impl Default for SockaddrStorage {
    fn default() -> Self {
        Self {
            ss_family: 0,
            _pad: [0u8; 126],
        }
    }
}

/// `struct iovec` — base / length pair for scatter-gather
/// IO. Used by `readv / writev / sendmsg / recvmsg`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct IoVec {
    pub iov_base: *mut u8,
    pub iov_len: u64,
}

unsafe impl Sync for IoVec {}

/// `struct msghdr` — sendmsg / recvmsg argument bundle.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct MsgHdr {
    pub msg_name: *mut u8,
    pub msg_namelen: u32,
    pub msg_iov: *mut IoVec,
    pub msg_iovlen: u64,
    pub msg_control: *mut u8,
    pub msg_controllen: u64,
    pub msg_flags: i32,
}

unsafe impl Sync for MsgHdr {}

/// `struct cmsghdr` — fixed prefix of every control message.
/// Variable-length payload follows aligned to `size_of::<usize>()`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CmsgHdr {
    /// Total length of this cmsg (header + payload, excl. tail
    /// padding).
    pub cmsg_len: u64,
    /// Originating protocol layer — e.g. `SOL_SOCKET`.
    pub cmsg_level: i32,
    /// Type within the level — e.g. `SCM_RIGHTS`.
    pub cmsg_type: i32,
}

/// SOL_SOCKET — cmsg_level for ancillary messages routed through
/// the generic socket layer (SCM_RIGHTS, SCM_CREDENTIALS).
pub(crate) const SOL_SOCKET: i32 = 1;
