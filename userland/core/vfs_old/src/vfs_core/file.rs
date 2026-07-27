// SPDX-License-Identifier: GPL-2.0-only
//! VFS attribute and statistics structures.
//!
//! `VAttr` is the personality-neutral file attribute structure returned by
//! `VopMetaOps::getattr` and accepted by `setattr`. Each personality layer
//! translates it into its own shape (POSIX `struct stat`, Win32
//! `BY_HANDLE_FILE_INFORMATION`).
//!
//! `VStatfs` is the filesystem-level statistics structure returned by
//! `VopDataOps::statfs` and `VfsOps::statfs`.
//!
//! The old `OpenFile` struct is eliminated — per-fd state now lives in
//! `OpenObject` within `VfsState.open_objects` (see `server/open_object.rs`).

// =========================================================================
// Personality tags
// =========================================================================

/// POSIX personality.
pub(crate) const PERS_POSIX: u8 = 0;
/// Win32 personality.
pub(crate) const PERS_WIN32: u8 = 1;

// =========================================================================
// VAttr — personality-neutral file attributes
// =========================================================================

/// Personality-neutral file attribute snapshot.
///
/// Returned by `VopMetaOps::getattr`. Each personality translates into its
/// native shape:
/// - POSIX: `struct stat` (`mode`, `size`, `nlink`, `uid`, `gid`,
///   `atime`/`mtime`/`ctime`).
/// - Win32: `BY_HANDLE_FILE_INFORMATION` / `FILE_BASIC_INFORMATION`
///   with `CreationTime = btime`, `LastAccessTime = atime`,
///   `LastWriteTime = mtime`, `ChangeTime = ctime`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VAttr {
    /// File size in bytes.
    pub(crate) size: u64,
    /// Backing storage blocks (512B units).
    pub(crate) blocks: u64,
    /// Mode bits (type + permission).
    pub(crate) mode: u32,
    /// Owner user id.
    pub(crate) uid: u32,
    /// Owner group id.
    pub(crate) gid: u32,
    /// Hard link count.
    pub(crate) nlink: u32,
    /// Access time (nanoseconds since UNIX epoch).
    pub(crate) atime: u64,
    /// Modification time.
    pub(crate) mtime: u64,
    /// Status-change time.
    pub(crate) ctime: u64,
    /// Birth time (creation). 0 if not known.
    pub(crate) btime: u64,
    /// Containing device id.
    pub(crate) dev_id: u32,
    /// Character/block device id (for device files).
    pub(crate) rdev: u32,
}

impl VAttr {
    /// All-zero attribute — used as scratch before a `getattr` call fills it.
    pub(crate) const fn zeroed() -> Self {
        VAttr {
            size: 0,
            blocks: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            nlink: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            btime: 0,
            dev_id: 0,
            rdev: 0,
        }
    }
}

// =========================================================================
// VStatfs — filesystem-level statistics
// =========================================================================

/// Filesystem-level statistics, returned by `VfsOps::statfs`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VStatfs {
    /// Block size in bytes.
    pub(crate) bsize: u64,
    /// Total data blocks in filesystem.
    pub(crate) blocks: u64,
    /// Free blocks.
    pub(crate) bfree: u64,
    /// Free blocks available to unprivileged users.
    pub(crate) bavail: u64,
    /// Total file nodes.
    pub(crate) files: u64,
    /// Free file nodes.
    pub(crate) ffree: u64,
    /// Filesystem type name (null-padded ASCII).
    pub(crate) fs_type: [u8; 16],
    /// Mount flag snapshot (see `core/mount.rs`).
    pub(crate) flags: u32,
    /// Maximum filename length.
    pub(crate) name_max: u32,
}

impl VStatfs {
    pub(crate) const fn zeroed() -> Self {
        VStatfs {
            bsize: 0,
            blocks: 0,
            bfree: 0,
            bavail: 0,
            files: 0,
            ffree: 0,
            fs_type: [0; 16],
            flags: 0,
            name_max: 0,
        }
    }
}
