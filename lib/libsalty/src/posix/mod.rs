//! POSIX file I/O and process management wrappers
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Every POSIX operation is implemented as an IPC `Call` to either the VFS
//! server (`CAP_VFS_EP`) or the process manager (`CAP_PROCMGR_EP`). The
//! client packs arguments into a `SaltyMsg`, sends it, and unpacks the
//! reply. No kernel objects are created -- all state lives in the servers.
//!
//! # Data transfer chunking
//!
//! `posix_read` and `posix_write` transfer data in chunks of up to 152/144
//! bytes per IPC round-trip (limited by the 20-register message buffer).
//! Large reads/writes loop until the full count is transferred or EOF.
//!
//! # Path encoding
//!
//! Filesystem paths are packed into message registers by `pack_path()`:
//! `regs[offset]` = path length (max 64), followed by the path bytes
//! packed into subsequent u64 registers.

mod file;
mod socket;
mod poll;
mod pipe;
mod proc;
mod misc;
mod at;

pub use file::*;
pub use socket::*;
pub use poll::*;
pub use pipe::*;
pub use proc::*;
pub use misc::*;
pub use at::*;

use crate::consts::*;
use crate::types::*;

// Standard child CSpace layout (set by procmgr at spawn time)
const CAP_PROCMGR_EP: u64 = 3;
const CAP_VFS_EP: u64 = 4;

/// Convert a server error label to a negative POSIX errno code.
///
/// Servers return specific error codes in `reply.label`. This translates them
/// to negative errno values so saltyc can extract the correct errno.
pub(crate) fn salty_err_to_posix(label: u64) -> i32 {
    match label {
        SALTY_OK => 0,
        SALTY_NOT_FOUND => -2,                // ENOENT
        SALTY_ALREADY_EXISTS => -17,           // EEXIST
        SALTY_INVALID_ARGUMENT => -22,         // EINVAL
        SALTY_OUT_OF_MEMORY => -12,            // ENOMEM
        SALTY_BUSY => -16,                     // EBUSY
        SALTY_WOULD_BLOCK => -11,              // EAGAIN
        SALTY_BAD_ADDRESS => -14,              // EFAULT
        SALTY_INSUFFICIENT_RIGHTS => -13,      // EACCES
        SALTY_INVALID_CAPABILITY => -9,        // EBADF
        SALTY_DEADLOCK => -35,                 // EDEADLK
        SALTY_INVALID_OPERATION => -1,         // EPERM
        SALTY_OUT_OF_RANGE => -34,             // ERANGE
        SALTY_CANCELLED => -125,               // ECANCELED
        SALTY_CONN_REFUSED => -111,            // ECONNREFUSED
        SALTY_TIMED_OUT => -110,               // ETIMEDOUT
        _ => -5,                               // EIO (generic)
    }
}

/// Pack a null-terminated path into message registers starting at `offset`.
///
/// Writes the path length into `regs[offset]` and the path bytes (up to 64)
/// into `regs[offset+1..]`. Returns the path length.
pub(crate) unsafe fn pack_path(msg: *mut SaltyMsg, offset: usize, path: *const u8, max_len: usize) -> u8 {
    unsafe {
        let limit = if max_len < 128 { max_len } else { 128 };
        let mut path_len: u8 = 0;
        while (path_len as usize) < limit && *path.add(path_len as usize) != 0 {
            path_len += 1;
        }
        (*msg).regs[offset] = path_len as u64;
        for i in (offset + 1)..20 {
            (*msg).regs[i] = 0;
        }
        let dst = &mut (*msg).regs[offset + 1] as *mut u64 as *mut u8;
        for i in 0..path_len as usize {
            *dst.add(i) = *path.add(i);
        }
        path_len
    }
}
