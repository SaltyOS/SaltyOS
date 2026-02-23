//! select() implementation via poll()
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Implements `select(2)` by converting fd_set bitmasks to `PollFd` arrays
//! and calling `posix_poll`. The `FdSet` type holds 1024 bits (matching
//! `FD_SETSIZE`). C-callable `__fd_set`/`__fd_clr`/`__fd_isset`/`__fd_zero`
//! wrappers are exported for use by C code's `FD_*` macros.

use crate::errno;

const FD_SETSIZE: usize = 1024;
const NFDBITS: usize = 64;
const FD_SET_LONGS: usize = FD_SETSIZE / NFDBITS; // 16

#[repr(C)]
pub struct FdSet {
    pub fds_bits: [u64; FD_SET_LONGS],
}

fn fd_isset(fd: i32, set: *const FdSet) -> bool {
    if set.is_null() || fd < 0 || fd as usize >= FD_SETSIZE {
        return false;
    }
    unsafe {
        let word = fd as usize / NFDBITS;
        let bit = fd as usize % NFDBITS;
        ((*set).fds_bits[word] & (1u64 << bit)) != 0
    }
}

unsafe fn fd_set(fd: i32, set: *mut FdSet) {
    if set.is_null() || fd < 0 || fd as usize >= FD_SETSIZE {
        return;
    }
    unsafe {
        let word = fd as usize / NFDBITS;
        let bit = fd as usize % NFDBITS;
        (*set).fds_bits[word] |= 1u64 << bit;
    }
}

unsafe fn fd_zero(set: *mut FdSet) {
    if set.is_null() {
        return;
    }
    unsafe {
        for i in 0..FD_SET_LONGS {
            (*set).fds_bits[i] = 0;
        }
    }
}

#[repr(C)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

/// Synchronous I/O multiplexing.
///
/// Converts the `fd_set` bitmasks into a `PollFd` array (max 128 entries),
/// calls `posix_poll` internally, then translates the `revents` results
/// back into the caller's `fd_set` bitmasks. The timeout is converted from
/// `struct timeval` (sec + usec) to a millisecond value for `poll`.
///
/// Returns the number of ready file descriptors, 0 on timeout, or -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn select(
    nfds: i32,
    readfds: *mut FdSet,
    writefds: *mut FdSet,
    exceptfds: *mut FdSet,
    timeout: *mut Timeval,
) -> i32 {
    if nfds < 0 || nfds as usize > FD_SETSIZE {
        errno::set_errno(errno::EINVAL);
        return -1;
    }

    unsafe {
        // Count how many fds we need to poll
        let mut count: u32 = 0;
        for fd in 0..nfds {
            let in_read = fd_isset(fd, readfds);
            let in_write = fd_isset(fd, writefds);
            let in_except = fd_isset(fd, exceptfds);
            if in_read || in_write || in_except {
                count += 1;
            }
        }

        if count == 0 {
            // Just a timeout
            if !timeout.is_null() {
                let ms = (*timeout).tv_sec * 1000 + (*timeout).tv_usec / 1000;
                if ms > 0 {
                    let ts = salty::types::Timespec {
                        tv_sec: (*timeout).tv_sec as u64,
                        tv_nsec: ((*timeout).tv_usec * 1000) as u64,
                    };
                    let mut rem = salty::types::Timespec::zeroed();
                    salty::posix::posix_nanosleep(&raw const ts, &raw mut rem);
                }
            }
            return 0;
        }

        // Build PollFd array (max 128 for stack)
        const MAX_POLL: usize = 128;
        let actual_count = if (count as usize) < MAX_POLL {
            count as usize
        } else {
            MAX_POLL
        };
        let mut poll_fds: [salty::PollFd; MAX_POLL] = core::mem::zeroed();
        let mut fd_map: [i32; MAX_POLL] = [0; MAX_POLL]; // map index -> original fd
        let mut pi = 0;

        for fd in 0..nfds {
            if pi >= actual_count {
                break;
            }
            let in_read = fd_isset(fd, readfds);
            let in_write = fd_isset(fd, writefds);
            let in_except = fd_isset(fd, exceptfds);
            if in_read || in_write || in_except {
                poll_fds[pi].fd = fd;
                poll_fds[pi].events = 0;
                poll_fds[pi].revents = 0;
                if in_read {
                    poll_fds[pi].events |= salty::POLLIN;
                }
                if in_write {
                    poll_fds[pi].events |= salty::POLLOUT;
                }
                if in_except {
                    poll_fds[pi].events |= salty::POLLERR;
                }
                fd_map[pi] = fd;
                pi += 1;
            }
        }

        let timeout_ms: i32 = if timeout.is_null() {
            -1 // infinite
        } else {
            let ms = (*timeout).tv_sec * 1000 + (*timeout).tv_usec / 1000;
            if ms > i32::MAX as i64 {
                i32::MAX
            } else {
                ms as i32
            }
        };

        let ret = salty::posix::posix_poll(poll_fds.as_mut_ptr(), pi as u32, timeout_ms);

        if ret < 0 {
            errno::set_errno(-ret);
            return -1;
        }

        // Clear the fd_sets and re-populate with results
        if !readfds.is_null() {
            fd_zero(readfds);
        }
        if !writefds.is_null() {
            fd_zero(writefds);
        }
        if !exceptfds.is_null() {
            fd_zero(exceptfds);
        }

        let mut ready = 0;
        for i in 0..pi {
            let fd = fd_map[i];
            let rev = poll_fds[i].revents;
            let mut counted = false;

            if !readfds.is_null() && (rev & (salty::POLLIN | salty::POLLHUP | salty::POLLERR)) != 0
            {
                fd_set(fd, readfds);
                if !counted {
                    ready += 1;
                    counted = true;
                }
            }
            if !writefds.is_null() && (rev & salty::POLLOUT) != 0 {
                fd_set(fd, writefds);
                if !counted {
                    ready += 1;
                    counted = true;
                }
            }
            if !exceptfds.is_null() && (rev & salty::POLLERR) != 0 {
                fd_set(fd, exceptfds);
                if !counted {
                    ready += 1;
                }
            }
        }

        ready
    }
}

// C-callable FD_SET/FD_CLR/FD_ISSET/FD_ZERO functions
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __fd_set(fd: i32, set: *mut FdSet) {
    unsafe {
        fd_set(fd, set);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __fd_clr(fd: i32, set: *mut FdSet) {
    if set.is_null() || fd < 0 || fd as usize >= FD_SETSIZE {
        return;
    }
    unsafe {
        let word = fd as usize / NFDBITS;
        let bit = fd as usize % NFDBITS;
        (*set).fds_bits[word] &= !(1u64 << bit);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __fd_isset(fd: i32, set: *const FdSet) -> i32 {
    fd_isset(fd, set) as i32
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __fd_zero(set: *mut FdSet) {
    unsafe {
        fd_zero(set);
    }
}
