// SPDX-License-Identifier: GPL-2.0-only
//
//! VFS error type. `VfsError` is the personality-neutral error
//! enum — posix handlers return it, the personality layer
//! (`personality::posix` / `personality::win32`) translates it into
//! the personality's errno / NTSTATUS surface for the wire reply.
//!
//! `VfsError` is intentionally flat (no payload variants). Rich
//! audit context — file system instance, backend node, byte
//! offset, integrity sub-discriminator — is published through the
//! `audit_*` free functions so the error type stays one word and
//! `Result<T, VfsError>` does not bloat. Call sites that detect a
//! data integrity violation log via `audit_*` *and* return the
//! appropriate flat variant.

use crate::core::identity::{BackendNodeId, FsInstanceId};

/// Personality-neutral error variants. The personality layer
/// translates these into POSIX errno / NTSTATUS for the wire
/// reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum VfsError {
    /// Bad fd / handle.
    BadF = 1,
    /// Permission denied.
    Acces = 2,
    /// Resource busy.
    Busy = 3,
    /// File exists.
    Exist = 4,
    /// Directory not empty.
    NotEmpty = 5,
    /// Cross-device operation.
    XDev = 6,
    /// I/O error from backend (catch-all for non-classified
    /// backend failures and detected data corruption).
    Io = 7,
    /// Is a directory (where a file was expected).
    IsDir = 8,
    /// Not a directory (where a directory was expected).
    NotDir = 9,
    /// File table / region table / arena exhausted.
    NoMem = 10,
    /// Out-of-range argument (offset, count, etc.).
    Inval = 11,
    /// File not found.
    NoEnt = 12,
    /// Symlink loop.
    Loop = 13,
    /// Operation not supported on this vnode / mount.
    NotSup = 14,
    /// File name too long.
    NameTooLong = 15,
    /// Read-only file system.
    RoFs = 16,
    /// Operation would block (`O_NONBLOCK`).
    Again = 17,
    /// Operation interrupted by signal.
    Intr = 18,
    /// Backend session torn down mid-flight.
    SessionTornDown = 19,
    /// PendingOp predecessor failed; first_error propagated.
    PredecessorFailed = 20,
    /// Backend reported a stale incarnation marker (live_gen /
    /// session_id mismatch with the in-flight request).
    StaleIncarnation = 21,
    /// Quota exhausted (per-client soft / hard limit).
    Quota = 22,
    /// Operation timed out.
    TimedOut = 23,
    /// fd refers to a non-tty object (`tcgetattr`/`tcsetattr`/`isatty`
    /// rejection — POSIX `ENOTTY`).
    NotTty = 24,
    /// Result-buffer too small to hold the reply (`getcwd` /
    /// `readlink` / similar — POSIX `ERANGE`).
    Range = 25,
}

impl VfsError {
    /// True when an optional metadata provider or value is absent.
    ///
    /// `NoEnt` means the provider exists but the requested metadata key is not
    /// present; `NotSup` means this vnode/filesystem does not implement that
    /// metadata namespace at all. Callers that layer optional policy over the
    /// core VFS model can use this to fall back to capability/vnode policy.
    #[inline]
    pub(crate) const fn is_optional_metadata_absent(self) -> bool {
        matches!(self, VfsError::NoEnt | VfsError::NotSup)
    }

    /// Map a `VFS_BACKEND_REPLY_*` label echoed by a backend
    /// (saltyfs daemon, netsrv, posix_ttysrv pty pair, blkdrv) to
    /// the matching `VfsError` variant. `VFS_BACKEND_REPLY_OK`
    /// is the success path and never lands here — call sites check
    /// it explicitly before invoking `from_backend_reply`. Unknown
    /// labels collapse to `VfsError::Io` so a backend that adds a
    /// new error code without coordinating with vfs cannot crash
    /// the dispatcher.
    #[inline]
    pub(crate) const fn from_backend_reply(label: u64) -> VfsError {
        use crate::ipc::protocol::backend::*;
        match label {
            VFS_BACKEND_REPLY_NOT_FOUND => VfsError::NoEnt,
            VFS_BACKEND_REPLY_IO_ERROR => VfsError::Io,
            VFS_BACKEND_REPLY_PERM => VfsError::Acces,
            VFS_BACKEND_REPLY_NO_SPACE => VfsError::NoMem,
            VFS_BACKEND_REPLY_EXIST => VfsError::Exist,
            VFS_BACKEND_REPLY_NOT_DIR => VfsError::NotDir,
            VFS_BACKEND_REPLY_IS_DIR => VfsError::IsDir,
            VFS_BACKEND_REPLY_NOT_EMPTY => VfsError::NotEmpty,
            VFS_BACKEND_REPLY_NAME_TOO_LONG => VfsError::NameTooLong,
            VFS_BACKEND_REPLY_INVALID => VfsError::Inval,
            VFS_BACKEND_REPLY_LOOP => VfsError::Loop,
            VFS_BACKEND_REPLY_RO_FS => VfsError::RoFs,
            VFS_BACKEND_REPLY_QUOTA => VfsError::Quota,
            VFS_BACKEND_REPLY_X_DEV => VfsError::XDev,
            VFS_BACKEND_REPLY_BUSY => VfsError::Busy,
            VFS_BACKEND_REPLY_NOT_SUPPORTED => VfsError::NotSup,
            _ => VfsError::Io,
        }
    }
}

/// `Result` alias used throughout the vfs core so handlers can
/// thread `?` cleanly across backend RPCs and resume helpers.
pub(crate) type VfsResult<T> = Result<T, VfsError>;

/// Sub-discriminator for `VfsError::Io`-class errors when the
/// completion router has detected a concrete integrity violation
/// (cross-mount completion, generation mismatch, malformed
/// reply, on-disk type-byte invariant violation). Threaded through
/// the saltyfs / netsrv completion arms via `audit_integrity_failure`;
/// surfaced in logs and in the personality reply via the matching
/// errno (typically EIO).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum IntegrityDetail {
    /// Backend reply quoted a session id that no longer matches
    /// the live session — the session torn down + reopened while
    /// the request was in flight.
    StaleSession = 1,
    /// Backend reply quoted an `fs_instance_id` that does not
    /// resolve to a live mount.
    UnknownMount = 2,
    /// Backend reply was malformed (label / register count out
    /// of bounds / zero-payload where data expected).
    Malformed = 3,
    /// Backend reply landed against a `PendingOp` whose
    /// `vnode_key` no longer resolves to a live vnode.
    StaleVnode = 4,
    /// Backend returned a stat record whose `S_IFMT` bits fall
    /// outside the POSIX file-type catalogue, or whose `mode`
    /// is zero in violation of the "every allocated inode carries
    /// a type" invariant.
    Inode = 5,
}

/// Audit-log a backend reply that overran its declared transfer
/// envelope (read returned more bytes than the descriptor
/// reserved, or write completion claimed bytes outside the SHM
/// slot). Caller has already mapped the failure to `VfsError::Io`
/// and is in the cleanup path. The audit log line is the only
/// surface that carries the structured `(fs, node, offset)` triple
/// — internal-only, never reaches the client.
#[inline]
pub(crate) fn audit_data_corrupt(fs: FsInstanceId, node: BackendNodeId, offset: u64) {
    trona_runtime::udebug!(|lb| {
        lb.str(b"[VFS] audit data_corrupt fs=");
        lb.hex(fs.raw());
        if node.is_valid() {
            lb.str(b" node.id=");
            lb.hex(node.id);
            lb.str(b" node.seq=");
            lb.dec(node.seq as u64);
        } else {
            lb.str(b" node=<invalid>");
        }
        lb.str(b" offset=");
        lb.hex(offset);
        lb.str(b"\n");
    });
}

/// Audit-log a backend reply that violated an integrity
/// invariant (stale session, unknown mount, malformed wire shape,
/// stale vnode, type-byte invariant). Caller has already mapped
/// the failure to `VfsError::Io` and is in the cleanup path. The
/// detail discriminator widens the catch-all into a structured
/// signal operators can grep for.
#[inline]
pub(crate) fn audit_integrity_failure(fs: FsInstanceId, detail: IntegrityDetail) {
    trona_runtime::udebug!(|lb| {
        lb.str(b"[VFS] audit integrity_failure fs=");
        lb.hex(fs.raw());
        lb.str(b" detail=");
        lb.dec(detail as u64);
        lb.str(b"\n");
    });
}
