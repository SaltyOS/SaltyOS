// SPDX-License-Identifier: GPL-2.0-only
//! POSIX open arbitration policy.
//!
//! Maps POSIX `O_*` flags into the personality-neutral `(access, deny)`
//! pair consumed by `vfs_core::arbitration::check_open`.
//!
//! POSIX semantics: reads and writes are freely shared — no implicit deny.
//! Explicit deny is installed only by `flock(LOCK_EX)` (handled separately
//! in the flock path, not here).

use trona_posix::consts::{
    O_ACCMODE, O_APPEND, O_CLOEXEC, O_CREAT, O_EXCL, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY,
};

use crate::fileops::open::OpenRequest;
use crate::personality::posix::consts::S_IFREG_L;
use crate::server::client::{flags_append_writes, flags_nonblocking, object_open_flags};
use crate::vfs_core::arbitration::{ACCESS_READ, ACCESS_WRITE};

/// Convert POSIX `O_*` open flags into an `(access, deny)` pair for the
/// unified arbitration layer.
///
/// Returns `(access_bits, deny_bits)`. POSIX never installs implicit deny
/// on open — `deny` is always 0. Explicit deny via `flock(LOCK_EX)` is
/// handled by a separate code path that calls `install_open` directly.
pub(crate) fn posix_open_arbitration(o_flags: u32) -> (u8, u8) {
    let access = match o_flags & O_ACCMODE {
        O_RDONLY => ACCESS_READ,
        O_WRONLY => ACCESS_WRITE,
        O_RDWR => ACCESS_READ | ACCESS_WRITE,
        _ => 0,
    };
    (access, 0)
}

pub(crate) fn posix_open_request(o_flags: u32, create_mode_bits: u32) -> OpenRequest {
    let (access, deny) = posix_open_arbitration(o_flags);
    let writable = matches!(o_flags & O_ACCMODE, O_WRONLY | O_RDWR);

    OpenRequest {
        backend_open_flags: o_flags,
        object_flags: object_open_flags(o_flags),
        create_mode: S_IFREG_L | (create_mode_bits & 0o777),
        win32_desired_access: 0,
        access,
        deny,
        append_on_write: flags_append_writes(o_flags),
        nonblocking: flags_nonblocking(o_flags),
        create_if_missing: (o_flags & O_CREAT) != 0,
        fail_if_exists: (o_flags & O_EXCL) != 0,
        truncate_existing: (o_flags & O_TRUNC) != 0,
        mutating_data: writable || (o_flags & (O_APPEND | O_TRUNC)) != 0,
        cloexec: (o_flags & O_CLOEXEC) != 0,
        delete_on_close: false,
    }
}
