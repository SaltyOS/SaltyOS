// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX inet wire shapes — sockaddr decoding / encoding,
//! `cmsghdr` walk over `msghdr.msg_control`, and the
//! `getsockname` / `getpeername` reply layouts.
//!
//! The `core::netsrv` bridge speaks personality-neutral
//! `(family, addr_bytes, port)` tuples. This module projects
//! those tuples onto AF_UNIX / AF_INET / AF_INET6 wire bytes
//! and back. Win32 will land its own equivalent in
//! `personality::win32::inet` once the Win32 process side
//! reaches the socket layer.
#![allow(dead_code)]

mod netsrv_client;

pub(crate) use self::netsrv_client::{
    close_conn, create_socket, handle_accept, handle_bind, handle_connect, handle_getpeername,
    handle_getsockname, handle_getsockopt, handle_listen, handle_recv, handle_send,
    handle_setsockopt, handle_shutdown, poll_status,
};

use super::consts::{SCM_CREDENTIALS, SCM_RIGHTS};
use super::types::{
    AF_INET, AF_INET6, AF_UNIX, CmsgHdr, In6Addr, InAddr, MsgHdr, SOCKADDR_UN_PATH_MAX, SOL_SOCKET,
    Sockaddr, SockaddrIn, SockaddrIn6, SockaddrStorage, SockaddrUn,
};

// =========================================================================
// AF_* helpers
// =========================================================================

/// Personality-neutral inet address family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AddressFamily {
    Unix,
    Inet,
    Inet6,
    /// Unrecognised family — wire encodes the raw `sa_family`
    /// byte so the dispatcher can return EAFNOSUPPORT.
    Other(u16),
}

#[inline]
pub(crate) const fn classify_family(sa_family: u16) -> AddressFamily {
    match sa_family {
        AF_UNIX => AddressFamily::Unix,
        AF_INET => AddressFamily::Inet,
        AF_INET6 => AddressFamily::Inet6,
        other => AddressFamily::Other(other),
    }
}

// =========================================================================
// AF_UNIX path classification
// =========================================================================

/// Linux UNIX-domain sockaddr namespaces. The pathname
/// namespace is filesystem-resident; the abstract namespace
/// (leading `\0`) lives in netsrv's session table; the
/// unnamed namespace (length 0 past the family) is for
/// freshly-`socket()`'d but unbound endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnixPathKind<'a> {
    /// Empty path — the socket has not been bound.
    Unnamed,
    /// `\0name` — abstract namespace; the byte slice excludes
    /// the leading NUL.
    Abstract(&'a [u8]),
    /// `/path/to/socket` — pathname namespace.
    Pathname(&'a [u8]),
}

/// Classify the body of a `sockaddr_un`, given its declared
/// length (= `sun_family.len() + path_len`). The path length
/// excludes the leading 2 bytes of `sun_family`.
pub(crate) fn classify_unix_path(addr: &SockaddrUn, addr_len: usize) -> UnixPathKind<'_> {
    let path_bytes = addr_len.saturating_sub(2);
    if path_bytes == 0 {
        return UnixPathKind::Unnamed;
    }
    let path_bytes = path_bytes.min(SOCKADDR_UN_PATH_MAX);
    let bytes = &addr.sun_path[..path_bytes];
    if bytes[0] == 0 {
        if bytes.len() == 1 {
            return UnixPathKind::Unnamed;
        }
        return UnixPathKind::Abstract(&bytes[1..]);
    }
    let trimmed = if let Some(nul) = bytes.iter().position(|&b| b == 0) {
        &bytes[..nul]
    } else {
        bytes
    };
    UnixPathKind::Pathname(trimmed)
}

// =========================================================================
// IPv4 helpers
// =========================================================================

/// Construct an `InAddr` from a host-order octet array.
#[inline]
pub(crate) const fn in_addr_from_octets(o: [u8; 4]) -> InAddr {
    let net_order =
        ((o[0] as u32) << 24) | ((o[1] as u32) << 16) | ((o[2] as u32) << 8) | (o[3] as u32);
    InAddr {
        s_addr: net_order.to_be(),
    }
}

#[inline]
pub(crate) const fn in_addr_to_octets(addr: InAddr) -> [u8; 4] {
    let host_order = u32::from_be(addr.s_addr);
    [
        ((host_order >> 24) & 0xFF) as u8,
        ((host_order >> 16) & 0xFF) as u8,
        ((host_order >> 8) & 0xFF) as u8,
        (host_order & 0xFF) as u8,
    ]
}

#[inline]
pub(crate) const fn make_sockaddr_in(addr: InAddr, port_host_order: u16) -> SockaddrIn {
    SockaddrIn {
        sin_family: AF_INET,
        sin_port: port_host_order.to_be(),
        sin_addr: addr,
        sin_zero: [0u8; 8],
    }
}

#[inline]
pub(crate) const fn make_sockaddr_in6(
    addr: In6Addr,
    port_host_order: u16,
    scope_id: u32,
) -> SockaddrIn6 {
    SockaddrIn6 {
        sin6_family: AF_INET6,
        sin6_port: port_host_order.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: addr,
        sin6_scope_id: scope_id,
    }
}

// =========================================================================
// sockaddr_storage projection
// =========================================================================

/// Project a `sockaddr_storage` view from a typed sockaddr_*.
/// Used by `getsockname` / `getpeername` reply emitters that
/// want to share a single buffer across AF_UNIX / AF_INET /
/// AF_INET6 cases.
pub(crate) fn store_sockaddr_in(addr: &SockaddrIn) -> (SockaddrStorage, usize) {
    let mut storage = SockaddrStorage::default();
    storage.ss_family = AF_INET;
    let bytes = unsafe {
        ::core::slice::from_raw_parts(
            (addr as *const SockaddrIn) as *const u8,
            ::core::mem::size_of::<SockaddrIn>(),
        )
    };
    let dst = unsafe {
        ::core::slice::from_raw_parts_mut(
            (&mut storage as *mut SockaddrStorage) as *mut u8,
            ::core::mem::size_of::<SockaddrStorage>(),
        )
    };
    let n = bytes.len().min(dst.len());
    dst[..n].copy_from_slice(&bytes[..n]);
    (storage, ::core::mem::size_of::<SockaddrIn>())
}

pub(crate) fn store_sockaddr_in6(addr: &SockaddrIn6) -> (SockaddrStorage, usize) {
    let mut storage = SockaddrStorage::default();
    storage.ss_family = AF_INET6;
    let bytes = unsafe {
        ::core::slice::from_raw_parts(
            (addr as *const SockaddrIn6) as *const u8,
            ::core::mem::size_of::<SockaddrIn6>(),
        )
    };
    let dst = unsafe {
        ::core::slice::from_raw_parts_mut(
            (&mut storage as *mut SockaddrStorage) as *mut u8,
            ::core::mem::size_of::<SockaddrStorage>(),
        )
    };
    let n = bytes.len().min(dst.len());
    dst[..n].copy_from_slice(&bytes[..n]);
    (storage, ::core::mem::size_of::<SockaddrIn6>())
}

// =========================================================================
// cmsghdr walk
// =========================================================================

/// Align `len` up to `size_of::<usize>()`, the alignment POSIX
/// CMSG macros use to walk the control buffer.
#[inline]
pub(crate) const fn cmsg_align(len: u64) -> u64 {
    let a = ::core::mem::size_of::<usize>() as u64;
    (len + a - 1) & !(a - 1)
}

/// Total bytes consumed by a cmsg of payload `data_len`,
/// including header + alignment padding. Used by the cmsg
/// emitter to know how much of `msg_controllen` to claim.
#[inline]
pub(crate) const fn cmsg_space(data_len: u64) -> u64 {
    cmsg_align((::core::mem::size_of::<CmsgHdr>() as u64) + cmsg_align(data_len))
}

/// Bytes the receiver should advance past the cmsg header to
/// reach the payload.
#[inline]
pub(crate) const fn cmsg_len(data_len: u64) -> u64 {
    (::core::mem::size_of::<CmsgHdr>() as u64) + data_len
}

/// SCM_RIGHTS payload — array of file descriptors (i32). The
/// dispatch entry parses this when it sees `SOL_SOCKET +
/// SCM_RIGHTS` and routes to `posix::scm_rights::install`.
#[inline]
pub(crate) const fn is_scm_rights(level: i32, ty: i32) -> bool {
    level == SOL_SOCKET && ty == SCM_RIGHTS
}

/// SCM_CREDENTIALS payload — `struct ucred` (pid, uid, gid).
#[inline]
pub(crate) const fn is_scm_credentials(level: i32, ty: i32) -> bool {
    level == SOL_SOCKET && ty == SCM_CREDENTIALS
}

// =========================================================================
// sockaddr field accessors
// =========================================================================

#[inline]
pub(crate) fn sa_family_of(generic: &Sockaddr) -> u16 {
    generic.sa_family
}

/// Read the sockaddr_in `port` field as host-order u16.
#[inline]
pub(crate) const fn sin_port_host(addr: &SockaddrIn) -> u16 {
    u16::from_be(addr.sin_port)
}

/// Read the sockaddr_in6 `port` field as host-order u16.
#[inline]
pub(crate) const fn sin6_port_host(addr: &SockaddrIn6) -> u16 {
    u16::from_be(addr.sin6_port)
}

/// Validate the byte length of a recvmsg-supplied
/// `msg_controllen` against the minimum needed to carry one
/// cmsg of `data_len`. Returns `false` if the buffer is too
/// small — the dispatcher then sets `MSG_CTRUNC` on the reply
/// and emits as many cmsgs as fit.
#[inline]
pub(crate) const fn cmsg_buffer_fits(buf_len: u64, data_len: u64) -> bool {
    buf_len >= cmsg_space(data_len)
}

#[inline]
pub(crate) const fn msghdr_has_control(hdr: &MsgHdr) -> bool {
    hdr.msg_controllen > 0
}
