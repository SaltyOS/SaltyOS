// SPDX-License-Identifier: GPL-2.0-only
//
//! Personality-neutral file-attribute snapshot. The wire-side
//! VFS_STAT / VFS_FSTAT replies project from these fields; each
//! personality further reformats into its own `struct stat` /
//! `BY_HANDLE_FILE_INFORMATION` shape.

use crate::core::identity::FsInstanceId;
use crate::core::vnode::VnodeKind;

/// `VAttr.valid` bit — `mode` field is set.
pub(crate) const VATTR_MODE: u32 = 1 << 0;
/// `VAttr.valid` bit — `uid` field is set.
pub(crate) const VATTR_UID: u32 = 1 << 1;
/// `VAttr.valid` bit — `gid` field is set.
pub(crate) const VATTR_GID: u32 = 1 << 2;
/// `VAttr.valid` bit — `atime` field is set.
pub(crate) const VATTR_ATIME: u32 = 1 << 3;
/// `VAttr.valid` bit — `mtime` field is set.
pub(crate) const VATTR_MTIME: u32 = 1 << 4;
/// `VAttr.valid` bit — `ctime` field is set.
pub(crate) const VATTR_CTIME: u32 = 1 << 5;
/// `VAttr.valid` bit — `size` field is set. Reserved; truncate
/// uses `meta.truncate` rather than `meta.setattr` so this bit
/// is unused in the current callers — defined for completeness.
pub(crate) const VATTR_SIZE: u32 = 1 << 6;

pub(crate) const MODE_TYPE_DIR: u32 = 0o040000;
pub(crate) const MODE_TYPE_REG: u32 = 0o100000;
pub(crate) const MODE_TYPE_LNK: u32 = 0o120000;

/// Personality-neutral file attribute record. Backends populate
/// these through their filesystem-specific vops implementations;
/// the personality layer converts to its own stat shape just
/// before reply.
///
/// `meta.setattr` callers fill only the fields they want to mutate
/// and stamp the matching `VATTR_*` bits in `valid`. Backends
/// inspect `valid` rather than guessing from sentinel values — a
/// caller that wants `chmod(path, 0)` (clear all permission bits)
/// stamps `valid |= VATTR_MODE` with `mode = 0`, distinct from a
/// caller that wants chown only (`valid |= VATTR_UID | VATTR_GID`,
/// `mode` left at zero but bit not set).
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub(crate) struct VAttr {
    /// Bitmask of `VATTR_*` — which fields are populated.
    /// `meta.getattr` fills every field and leaves `valid` zero
    /// (callers read each field directly). `meta.setattr` reads
    /// `valid` to know which fields to apply.
    pub valid: u32,
    /// Mount instance the file lives on. Personality layers
    /// project to `st_dev` (POSIX) / `dwVolumeSerialNumber`
    /// (Win32).
    pub fs_instance_id: FsInstanceId,
    /// Backend node id.
    pub backend_node_id: u64,
    /// Backend node incarnation seq. Matches
    /// `BackendNodeId.seq`.
    pub backend_seq: u32,
    /// Vnode kind discriminator.
    pub kind: VnodeKind,
    /// POSIX mode bits — type + permission bits packed.
    pub mode: u32,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Hard-link count.
    pub nlink: u32,
    /// File size in bytes.
    pub size: u64,
    /// Block count (512-byte units, POSIX convention).
    pub blocks: u64,
    /// Last access time, ns since unix epoch.
    pub atime: u64,
    /// Last modify time, ns since unix epoch.
    pub mtime: u64,
    /// Last status-change time, ns since unix epoch.
    pub ctime: u64,
}

impl VAttr {
    pub(crate) const EMPTY: Self = Self {
        valid: 0,
        fs_instance_id: FsInstanceId::INVALID,
        backend_node_id: 0,
        backend_seq: 0,
        kind: VnodeKind::Empty,
        mode: 0,
        uid: 0,
        gid: 0,
        nlink: 0,
        size: 0,
        blocks: 0,
        atime: 0,
        mtime: 0,
        ctime: 0,
    };

    /// Zero-initialised attribute record. Backends use this as
    /// the starting point and overwrite the fields they know.
    /// Equivalent to `EMPTY` — kept as a separate constructor for
    /// readability at fill sites.
    #[inline]
    pub(crate) const fn zeroed() -> Self {
        Self::EMPTY
    }
}

/// Personality-neutral filesystem-wide statistics. Surfaced by
/// `VfsOps::statfs` and by `VopDataOps::statfs` for per-vnode
/// statvfs queries. Each personality reformats into its native
/// shape (POSIX `struct statvfs`, Win32 `GetDiskFreeSpaceEx`)
/// just before reply.
pub(crate) const VSTATFS_NAME_MAX: usize = 32;

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub(crate) struct VStatfs {
    /// Block size, bytes.
    pub bsize: u32,
    /// Fundamental block size, bytes.
    pub frsize: u32,
    /// Total data blocks.
    pub blocks: u64,
    /// Free blocks.
    pub bfree: u64,
    /// Free blocks available to non-root.
    pub bavail: u64,
    /// Total inodes.
    pub files: u64,
    /// Free inodes.
    pub ffree: u64,
    /// Free inodes available to non-root.
    pub favail: u64,
    /// Filesystem id (mount-instance unique).
    pub fsid: u64,
    /// Mount flags (read-only, sync, ...).
    pub flag: u32,
    /// Maximum file name length.
    pub namemax: u32,
    /// Filesystem implementation name, filled by the backend.
    pub fs_name_len: u8,
    /// Volume label length. Zero means the backend did not expose
    /// a label through statfs.
    pub volume_label_len: u8,
    pub _reserved: [u8; 6],
    pub fs_name: [u8; VSTATFS_NAME_MAX],
    pub volume_label: [u8; VSTATFS_NAME_MAX],
}

impl VStatfs {
    pub(crate) const EMPTY: Self = Self {
        bsize: 0,
        frsize: 0,
        blocks: 0,
        bfree: 0,
        bavail: 0,
        files: 0,
        ffree: 0,
        favail: 0,
        fsid: 0,
        flag: 0,
        namemax: 0,
        fs_name_len: 0,
        volume_label_len: 0,
        _reserved: [0; 6],
        fs_name: [0; VSTATFS_NAME_MAX],
        volume_label: [0; VSTATFS_NAME_MAX],
    };

    #[inline]
    pub(crate) const fn zeroed() -> Self {
        Self::EMPTY
    }

    pub(crate) fn set_fs_name(&mut self, name: &[u8]) {
        let n = name.len().min(VSTATFS_NAME_MAX).min(u8::MAX as usize);
        self.fs_name = [0; VSTATFS_NAME_MAX];
        self.fs_name[..n].copy_from_slice(&name[..n]);
        self.fs_name_len = n as u8;
    }

    pub(crate) fn set_volume_label(&mut self, label: &[u8]) {
        let n = label.len().min(VSTATFS_NAME_MAX).min(u8::MAX as usize);
        self.volume_label = [0; VSTATFS_NAME_MAX];
        self.volume_label[..n].copy_from_slice(&label[..n]);
        self.volume_label_len = n as u8;
    }

    pub(crate) fn fs_name(&self) -> &[u8] {
        let n = (self.fs_name_len as usize).min(VSTATFS_NAME_MAX);
        &self.fs_name[..n]
    }

    pub(crate) fn volume_label(&self) -> &[u8] {
        let n = (self.volume_label_len as usize).min(VSTATFS_NAME_MAX);
        &self.volume_label[..n]
    }
}
