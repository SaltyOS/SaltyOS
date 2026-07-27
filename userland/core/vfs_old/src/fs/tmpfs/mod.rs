// SPDX-License-Identifier: GPL-2.0-only
//! Tmpfs — independent in-memory filesystem with size/inode limits.
//!
//! tmpfs is a completely independent filesystem that does NOT reuse ramfs
//! code. It has its own block chain pool, dirent array, symlink pool, and
//! memory accounting (configurable size and inode limits).
//!
//! # Mount options
//!
//! - `size=NNN` — maximum total data bytes (0 = unlimited)
//! - `nr_inodes=NNN` — maximum inode count (0 = unlimited)
//!
//! # Module layout
//!
//! - [`types`] — `TmpfsVnodeData`, `TmpfsMountData`
//! - [`pool`] — Per-mount pool management (allocation, growth, block chains, accounting)
//! - [`vops`] — `VopVector` function implementations
//! - [`vfsops`] — `VfsOps` function implementations

mod pool;
mod types;
mod vfsops;
mod vops;

pub(crate) use types::{TmpfsMountData, TmpfsVnodeData};

use crate::vfs_core::error::VfsResult;
use crate::vfs_core::vfs::{VfsOps, register_fs_type};
use crate::vfs_core::vop::{
    DATA_OPS_DEFAULT, DataExecMode, META_OPS_DEFAULT, VopDataOps, VopMetaOps, VopVector,
};

// =========================================================================
// Static dispatch tables
// =========================================================================

/// Tmpfs vnode operation dispatch table.
pub(crate) static TMPFS_VOPS: VopVector = VopVector {
    meta: VopMetaOps {
        lookup: vops::tmpfs_lookup,
        lookup_ci: vops::tmpfs_lookup,
        create: vops::tmpfs_create,
        mkdir: vops::tmpfs_mkdir,
        symlink: vops::tmpfs_symlink,
        unlink: vops::tmpfs_unlink,
        rmdir: vops::tmpfs_rmdir,
        link: vops::tmpfs_link,
        rename: vops::tmpfs_rename,
        open: vops::tmpfs_open,
        close: vops::tmpfs_close,
        getattr: vops::tmpfs_getattr,
        setattr: vops::tmpfs_setattr,
        access: vops::tmpfs_access,
        readlink: vops::tmpfs_readlink,
        truncate: vops::tmpfs_truncate,
        inactive: vops::tmpfs_inactive,
    },
    data: VopDataOps {
        read_mode: DataExecMode::WorkerSafe,
        write_mode: DataExecMode::WorkerSafe,
        readdir_mode: DataExecMode::WorkerSafe,
        read: vops::tmpfs_read,
        write: vops::tmpfs_write,
        fsync: vops::tmpfs_fsync,
        readdir: vops::tmpfs_readdir,
        statfs: vops::tmpfs_statfs,
        ..DATA_OPS_DEFAULT
    },
};

/// Tmpfs filesystem-level operations.
pub(crate) static TMPFS_VFSOPS: VfsOps = VfsOps {
    mount: vfsops::tmpfs_mount,
    unmount: vfsops::tmpfs_unmount,
    root: vfsops::tmpfs_root,
    vget: vfsops::tmpfs_vget,
    statfs: vfsops::tmpfs_statfs,
    sync: vfsops::tmpfs_sync,
};

// =========================================================================
// Registration
// =========================================================================

/// Register the `tmpfs` filesystem type. Called during VFS bootstrap Stage 2.
pub(crate) unsafe fn register() -> VfsResult<()> {
    unsafe { register_fs_type(b"tmpfs", &raw const TMPFS_VFSOPS, &raw const TMPFS_VOPS) }
}
