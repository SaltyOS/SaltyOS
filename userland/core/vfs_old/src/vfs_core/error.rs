// SPDX-License-Identifier: GPL-2.0-only
//! VFS core error type and TRONA_* mapping.
//!
//! Personality-neutral error codes returned by VopVector operations and
//! internal VFS helpers. Each personality layer (`personality/posix/errno.rs`,
//! `personality/win32/errno.rs`) converts these into the error code shape
//! expected by its callers (POSIX errno, Win32 NTSTATUS/ERROR_*).
//!
//! The mapping to `TRONA_*` wire labels lives in `ipc/reply.rs`. VFS op
//! functions themselves never touch `TronaMsg` — ordinary helpers return
//! `Result<_, VfsError>`, while VOP entrypoints return
//! `crate::vfs_core::outcome::VopOutcome<_>`.

use trona_runtime::core::server_consts::TRONA_NOT_CONNECTED;
use uapi::*;

use crate::vfs_core::identity::FsInstanceId;

/// Detail component of [`VfsError::IntegrityFailure`]. Separate from
/// `DataCorrupt` because integrity violations may be detected without
/// a specific offending byte offset (e.g. superblock CRC, B-tree
/// invariant check). Audit logs want the kind to triage.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum IntegrityDetail {
    /// Superblock CRC mismatch or self-referential corruption.
    Superblock,
    /// B-tree structural invariant violated (parent/child pointer
    /// mismatch, key ordering, free-leaf bitmap inconsistency, …).
    Btree,
    /// Xattr tree structural invariant violated.
    Xattr,
    /// Inode body CRC or nlink-vs-dirent consistency mismatch.
    Inode,
    /// Catch-all for personality-visible integrity errors the backend
    /// has not classified yet. Always worth logging.
    Other,
}

/// VFS core error code — personality-neutral.
///
/// All plain-unit variants carry a stable discriminant (1..=21) matching the
/// original `#[repr(u32)]` layout for downstream conversions. Payload
/// variants (`DataCorrupt`, `IntegrityFailure`) extend the surface so
/// the backend identity and location travel with the error into the
/// audit log.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum VfsError {
    /// Path component or object not found.
    NotFound,
    /// Expected a directory, got a non-directory.
    NotDir,
    /// Expected a non-directory, got a directory.
    IsDir,
    /// Symbolic link loop exceeded depth limit.
    Loop,
    /// Backend I/O failure (IPC, device, etc.).
    Io,
    /// Operation not supported by this filesystem.
    NotSupported,
    /// Permission denied (credential check failed).
    Perm,
    /// Out of space (storage, inode pool, etc.).
    NoSpace,
    /// Path component already exists (O_CREAT | O_EXCL).
    Exists,
    /// Name or path too long.
    NameTooLong,
    /// Invalid argument (malformed path, bad flags, etc.).
    Inval,
    /// Resource busy (mount has live references, etc.).
    Busy,
    /// Directory entry references a stale inode.
    NoEntry,
    /// Open would violate an existing share-mode restriction.
    SharingViolation,
    /// Vnode has delete-pending flag; new opens rejected.
    DeletePending,
    /// Mount is read-only and this op would mutate.
    ReadOnly,
    /// Value too large (e.g. xattr inline limit exceeded).
    TooLarge,
    /// Bad handle (FD, vnode reference, etc.).
    BadHandle,
    /// Operation would block — used by backends signalling cache-miss
    /// / credit-exhaustion to the dispatch layer so it defers to a
    /// worker thread or returns `TRONA_BUSY`.
    WouldBlock,
    /// Operation crosses a mount boundary. Rename and link must
    /// reject cross-mount requests pre-issue because the backend
    /// cannot interpret foreign vnodes (their private data is a
    /// different backend's struct layout); a bare cast would
    /// reinterpret arbitrary bytes as if they were the current
    /// backend's vnode data. Maps to POSIX `EXDEV`.
    CrossDevice,
    /// Backend session was torn down mid-operation — either the
    /// backend process crashed and its session cap was revoked, or
    /// the client explicitly unmounted while this op was in flight.
    /// Surfaced on in-flight `PendingOp`s synthesised as cancelled
    /// completions; maps to POSIX `ENOTCONN` so clients distinguish
    /// "backend went away" from a transient `EIO`.
    SessionTornDown,
    /// Data checksum mismatch on a specific block. Carries the
    /// backend-session identity and the offending `BackendNodeId` +
    /// byte offset so an audit log entry has enough context to locate
    /// the affected inode without re-reading the disk. Maps to POSIX
    /// `EIO`; clients retry-once policy is left to the personality.
    DataCorrupt {
        fs: FsInstanceId,
        node: trona_protocol::BackendNodeId,
        offset: u64,
    },
    /// Backend integrity invariant violated (superblock CRC, B-tree
    /// shape, xattr tree, inode body CRC, …). Carries the backend
    /// identity + [`IntegrityDetail`]. Maps to POSIX `EIO` at the
    /// personality boundary.
    IntegrityFailure {
        fs: FsInstanceId,
        detail: IntegrityDetail,
    },
    /// Stale vnode incarnation — the backend's `seq` counter bumped
    /// between the client's request issue and the completion arrival,
    /// meaning the inode the caller thought it held a handle to has
    /// since been freed and recycled. Wire-encoded as
    /// `CORRELATION_F_STALE_INCARNATION`. Maps to POSIX `ESTALE`.
    Stale,
}

impl VfsError {
    /// Convert to a TRONA_* error code for IPC reply.
    #[inline]
    pub(crate) fn to_trona(self) -> u64 {
        match self {
            VfsError::NotFound => TRONA_NOT_FOUND,
            VfsError::NotDir => TRONA_NOT_DIRECTORY,
            VfsError::IsDir => TRONA_IS_DIRECTORY,
            VfsError::Loop => TRONA_LOOP,
            VfsError::Io => TRONA_IO_ERROR,
            VfsError::NotSupported => TRONA_NOT_SUPPORTED,
            VfsError::Perm => TRONA_INSUFFICIENT_RIGHTS,
            VfsError::NoSpace => TRONA_OUT_OF_MEMORY,
            VfsError::Exists => TRONA_ALREADY_EXISTS,
            VfsError::NameTooLong => TRONA_INVALID_ARGUMENT,
            VfsError::Inval => TRONA_INVALID_ARGUMENT,
            VfsError::Busy => TRONA_BUSY,
            VfsError::NoEntry => TRONA_NOT_FOUND,
            VfsError::SharingViolation => TRONA_BUSY,
            VfsError::DeletePending => TRONA_NOT_FOUND,
            VfsError::ReadOnly => TRONA_READONLY,
            VfsError::TooLarge => TRONA_TOO_LARGE,
            VfsError::BadHandle => TRONA_INVALID_ARGUMENT,
            VfsError::WouldBlock => TRONA_WOULD_BLOCK,
            VfsError::CrossDevice => TRONA_CROSS_DEVICE,
            VfsError::SessionTornDown => TRONA_NOT_CONNECTED,
            VfsError::DataCorrupt { .. } => TRONA_IO_ERROR,
            VfsError::IntegrityFailure { .. } => TRONA_IO_ERROR,
            VfsError::Stale => trona_runtime::core::server_consts::server::TRONA_STALE,
        }
    }

    /// Compact numeric code suitable for logging. Matches the
    /// historical `#[repr(u32)]` discriminant (1..=19) for the
    /// unit variants.
    #[inline]
    pub(crate) fn discriminant(self) -> u32 {
        match self {
            VfsError::NotFound => 1,
            VfsError::NotDir => 2,
            VfsError::IsDir => 3,
            VfsError::Loop => 4,
            VfsError::Io => 5,
            VfsError::NotSupported => 6,
            VfsError::Perm => 7,
            VfsError::NoSpace => 8,
            VfsError::Exists => 9,
            VfsError::NameTooLong => 10,
            VfsError::Inval => 11,
            VfsError::Busy => 12,
            VfsError::NoEntry => 13,
            VfsError::SharingViolation => 14,
            VfsError::DeletePending => 15,
            VfsError::ReadOnly => 16,
            VfsError::TooLarge => 17,
            VfsError::BadHandle => 18,
            VfsError::WouldBlock => 19,
            VfsError::CrossDevice => 20,
            VfsError::SessionTornDown => 21,
            VfsError::DataCorrupt { .. } => 22,
            VfsError::IntegrityFailure { .. } => 23,
            VfsError::Stale => 24,
        }
    }

    /// Emit a one-line audit entry for integrity-class errors.
    /// Returns `true` if the error produced a log line (i.e. the
    /// variant carried audit-worthy identity information), `false`
    /// otherwise. The caller owns the decision to suppress duplicates
    /// for retry-paired reads.
    pub(crate) fn audit_log(self) -> bool {
        match self {
            VfsError::DataCorrupt { fs, node, offset } => {
                trona_runtime::uwarn!(|_lb| {
                    _lb.str(b"[vfs:audit] DataCorrupt fs=");
                    _lb.dec(fs.raw());
                    _lb.str(b" ino=");
                    _lb.dec(node.ino);
                    _lb.str(b" seq=");
                    _lb.dec(node.seq as u64);
                    _lb.str(b" off=");
                    _lb.dec(offset);
                    _lb.str(b"\n");
                });
                true
            }
            VfsError::IntegrityFailure { fs, detail } => {
                trona_runtime::uwarn!(|_lb| {
                    _lb.str(b"[vfs:audit] IntegrityFailure fs=");
                    _lb.dec(fs.raw());
                    _lb.str(b" detail=");
                    _lb.str(integrity_detail_tag(detail));
                    _lb.str(b"\n");
                });
                true
            }
            _ => false,
        }
    }
}

#[inline]
fn integrity_detail_tag(detail: IntegrityDetail) -> &'static [u8] {
    match detail {
        IntegrityDetail::Superblock => b"superblock",
        IntegrityDetail::Btree => b"btree",
        IntegrityDetail::Xattr => b"xattr",
        IntegrityDetail::Inode => b"inode",
        IntegrityDetail::Other => b"other",
    }
}

/// Convenience alias for Results returned by VopVector operations.
pub(crate) type VfsResult<T> = core::result::Result<T, VfsError>;
