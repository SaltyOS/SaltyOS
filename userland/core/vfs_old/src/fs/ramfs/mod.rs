// SPDX-License-Identifier: GPL-2.0-only
//! Ramfs — in-memory filesystem with Vnode-native implementation.
//!
//! This module replaces the legacy flat-inode ramfs with a proper
//! `VopVector` + `VfsOps` implementation that uses per-mount pools
//! for vnode data, writable block chains, and symlink targets.
//!
//! # Module layout
//!
//! - [`types`] — `RamfsVnodeData`, `RamfsMountData`
//! - [`pool`] — Per-mount pool management (allocation, growth, block chains)
//! - [`vops`] — `VopVector` function implementations
//! - [`vfsops`] — `VfsOps` function implementations

pub(crate) mod pool;
mod types;
mod vfsops;
mod vops;

pub(crate) use types::{RamfsMountData, RamfsVnodeData};

use crate::vfs_core::error::VfsResult;
use crate::vfs_core::vfs::{VfsOps, register_fs_type};
use crate::vfs_core::vop::{
    DATA_OPS_DEFAULT, DataExecMode, META_OPS_DEFAULT, VopDataOps, VopMetaOps, VopVector,
};

// =========================================================================
// Static dispatch tables
// =========================================================================

/// Ramfs vnode operation dispatch table.
pub(crate) static RAMFS_VOPS: VopVector = VopVector {
    meta: VopMetaOps {
        lookup: vops::ramfs_lookup,
        lookup_ci: vops::ramfs_lookup,
        create: vops::ramfs_create,
        mkdir: vops::ramfs_mkdir,
        symlink: vops::ramfs_symlink,
        unlink: vops::ramfs_unlink,
        rmdir: vops::ramfs_rmdir,
        link: vops::ramfs_link,
        rename: vops::ramfs_rename,
        open: vops::ramfs_open,
        close: vops::ramfs_close,
        getattr: vops::ramfs_getattr,
        setattr: vops::ramfs_setattr,
        access: vops::ramfs_access,
        readlink: vops::ramfs_readlink,
        truncate: vops::ramfs_truncate,
        inactive: vops::ramfs_inactive,
    },
    data: VopDataOps {
        read_mode: DataExecMode::WorkerSafe,
        write_mode: DataExecMode::WorkerSafe,
        readdir_mode: DataExecMode::WorkerSafe,
        read: vops::ramfs_read,
        write: vops::ramfs_write,
        fsync: vops::ramfs_fsync,
        readdir: vops::ramfs_readdir,
        statfs: vops::ramfs_statfs,
        ..DATA_OPS_DEFAULT
    },
};

/// Ramfs filesystem-level operations.
pub(crate) static RAMFS_VFSOPS: VfsOps = VfsOps {
    mount: vfsops::ramfs_mount,
    unmount: vfsops::ramfs_unmount,
    root: vfsops::ramfs_root,
    vget: vfsops::ramfs_vget,
    statfs: vfsops::ramfs_statfs,
    sync: vfsops::ramfs_sync,
};

// =========================================================================
// Registration
// =========================================================================

/// Register the `ramfs` filesystem type. Called during VFS bootstrap Stage 2.
pub(crate) unsafe fn register() -> VfsResult<()> {
    unsafe { register_fs_type(b"ramfs", &raw const RAMFS_VFSOPS, &raw const RAMFS_VOPS) }
}
