// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX poll / epoll personality bits.
//!
//! `POLL*` event masks are read by `poll(2)` callers in
//! `pollfd::events` (request) and emitted by vfs in
//! `pollfd::revents` (response). `EPOLL*` overlays the same value
//! space (the bottom 16 bits agree with `POLL*`) plus higher
//! Linux-specific flags (`EPOLLET`, `EPOLLONESHOT`, `EPOLLWAKEUP`,
//! `EPOLLEXCLUSIVE`).
//!
//! Wire types (`PollFd`, `EpollEvent`) live in
//! [`super::types`]; this module owns the bit constants and the
//! `EPOLL_CTL_*` opcode discriminator.
#![allow(dead_code)]

mod entry;

pub(crate) use self::entry::{complete_waiter, handle};

// =========================================================================
// POLL* — events / revents bits for poll(2)
// =========================================================================

pub(crate) const POLLIN: i16 = 0x0001;
pub(crate) const POLLPRI: i16 = 0x0002;
pub(crate) const POLLOUT: i16 = 0x0004;
pub(crate) const POLLERR: i16 = 0x0008;
pub(crate) const POLLHUP: i16 = 0x0010;
pub(crate) const POLLNVAL: i16 = 0x0020;
pub(crate) const POLLRDNORM: i16 = 0x0040;
pub(crate) const POLLRDBAND: i16 = 0x0080;
pub(crate) const POLLWRNORM: i16 = 0x0100;
pub(crate) const POLLWRBAND: i16 = 0x0200;
pub(crate) const POLLMSG: i16 = 0x0400;
pub(crate) const POLLREMOVE: i16 = 0x1000;
pub(crate) const POLLRDHUP: i16 = 0x2000;

// =========================================================================
// EPOLL* — events bits for epoll_event::events
//
// The low 16 bits agree with POLL* by ABI contract; the
// constants are restated as `u32` (POLL* are i16) so callers
// don't need to cast at every call-site.
// =========================================================================

pub(crate) const EPOLLIN: u32 = 0x0001;
pub(crate) const EPOLLPRI: u32 = 0x0002;
pub(crate) const EPOLLOUT: u32 = 0x0004;
pub(crate) const EPOLLERR: u32 = 0x0008;
pub(crate) const EPOLLHUP: u32 = 0x0010;
pub(crate) const EPOLLNVAL: u32 = 0x0020;
pub(crate) const EPOLLRDNORM: u32 = 0x0040;
pub(crate) const EPOLLRDBAND: u32 = 0x0080;
pub(crate) const EPOLLWRNORM: u32 = 0x0100;
pub(crate) const EPOLLWRBAND: u32 = 0x0200;
pub(crate) const EPOLLMSG: u32 = 0x0400;
pub(crate) const EPOLLRDHUP: u32 = 0x2000;

/// Linux-specific high bits — these have no `POLL*` analogue.
pub(crate) const EPOLLEXCLUSIVE: u32 = 1 << 28;
pub(crate) const EPOLLWAKEUP: u32 = 1 << 29;
pub(crate) const EPOLLONESHOT: u32 = 1 << 30;
pub(crate) const EPOLLET: u32 = 1 << 31;

// =========================================================================
// EPOLL_CTL_* — opcode for epoll_ctl(2)
// =========================================================================

pub(crate) const EPOLL_CTL_ADD: i32 = 1;
pub(crate) const EPOLL_CTL_DEL: i32 = 2;
pub(crate) const EPOLL_CTL_MOD: i32 = 3;

// =========================================================================
// EPOLL_CLOEXEC — flag for epoll_create1(2)
//
// The wire value matches `O_CLOEXEC` so that
// `epoll_create1(EPOLL_CLOEXEC)` works regardless of which header
// the caller picked the constant up from.
// =========================================================================

pub(crate) const EPOLL_CLOEXEC: i32 = 0o2000000;

// =========================================================================
// `POLL*` ↔ vfs-internal wakeup-class projection
// =========================================================================

/// Map a POLL* mask onto the personality-neutral readiness flags
/// the wakeup queues (`owner::pipe_wait`, `inet_wait`,
/// `socket_wait`) carry. Callers OR the result into the wake mask
/// and the queues fan-out to all matching waiters.
///
/// Bits the caller did not request are stripped — `revents` only
/// reports what was requested in `events`, with the exception of
/// the always-reported `POLLERR` / `POLLHUP` / `POLLNVAL` triple.
#[inline]
pub(crate) const fn project_pollmask(events: i16) -> i16 {
    // `POLLERR` / `POLLHUP` / `POLLNVAL` are always reported in
    // revents regardless of whether the caller requested them.
    // The wakeup queue masks them in unconditionally so the
    // fan-out path stays branch-free.
    const ALWAYS_REPORTED: i16 = POLLERR | POLLHUP | POLLNVAL;
    events | ALWAYS_REPORTED
}
