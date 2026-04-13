// SPDX-License-Identifier: GPL-2.0-only
//! SaltyFS client — VopVector-based filesystem client module.
//!
//! Implements the VFS provider side of the VFS-SaltyFS IPC protocol.
//! All operations are thin RPC wrappers that issue IPC calls to the
//! SaltyFS server process and translate replies into VFS-native types.
//!
//! # Module layout
//!
//! - [`types`] — `SaltyfsMountData`, `SaltyfsVnodeData`
//! - [`pool`] — Per-mount vdata pool management
//! - [`rpc`] — Read-only IPC helpers (lookup, stat, read, readlink, getparent)
//! - [`mutate_rpc`] — Mutating IPC helpers (create, mkdir, write, chmod, ...)
//! - [`xattr_rpc`] — Extended attribute IPC helpers (SHM-based)
//! - [`readdir`] — SHM-based readdir streaming
//! - [`feature`] — Superblock feature flag negotiation
//! - [`vops`] — `VopMetaOps` + `VopDataOps` function implementations
//! - [`vfsops`] — `VfsOps` function implementations

mod feature;
mod mutate_rpc;
mod pool;
mod readdir;
mod rpc;
mod types;
mod vfsops;
mod vops;
mod xattr_rpc;

pub(crate) use types::{SaltyfsMountData, SaltyfsVnodeData};

use crate::vfs_core::error::VfsResult;
use crate::vfs_core::vfs::{register_fs_type, VfsOps};
use crate::vfs_core::vop::{VopVector, VopMetaOps, VopDataOps, META_OPS_DEFAULT, DATA_OPS_DEFAULT};

// =========================================================================
// Static dispatch tables
// =========================================================================

/// SaltyFS client vnode operation dispatch table.
pub(crate) static SALTYFS_VOPS: VopVector = VopVector {
    meta: VopMetaOps {
        lookup: vops::saltyfs_lookup,
        create: vops::saltyfs_create,
        mkdir: vops::saltyfs_mkdir,
        symlink: vops::saltyfs_symlink,
        unlink: vops::saltyfs_unlink,
        rmdir: vops::saltyfs_rmdir,
        link: vops::saltyfs_link,
        rename: vops::saltyfs_rename,
        open: vops::saltyfs_open,
        close: vops::saltyfs_close,
        getattr: vops::saltyfs_getattr,
        setattr: vops::saltyfs_setattr,
        access: vops::saltyfs_access,
        readlink: vops::saltyfs_readlink,
        truncate: vops::saltyfs_truncate,
        inactive: vops::saltyfs_inactive,
        ..META_OPS_DEFAULT
    },
    data: VopDataOps {
        read: vops::saltyfs_read,
        write: vops::saltyfs_write,
        fsync: vops::saltyfs_fsync,
        readdir: vops::saltyfs_readdir,
        getxattr: vops::saltyfs_getxattr,
        setxattr: vops::saltyfs_setxattr,
        listxattr: vops::saltyfs_listxattr,
        removexattr: vops::saltyfs_removexattr,
        statfs: vops::saltyfs_statfs,
        ..DATA_OPS_DEFAULT
    },
};

/// SaltyFS client filesystem-level operations.
pub(crate) static SALTYFS_VFSOPS: VfsOps = VfsOps {
    mount: vfsops::saltyfs_mount,
    unmount: vfsops::saltyfs_unmount,
    root: vfsops::saltyfs_root,
    vget: vfsops::saltyfs_vget,
    statfs: vfsops::saltyfs_statfs,
    sync: vfsops::saltyfs_sync,
};

// =========================================================================
// Registration
// =========================================================================

/// Register the `saltyfs` filesystem type. Called during VFS bootstrap Stage 2.
pub(crate) unsafe fn register() -> VfsResult<()> {
    unsafe {
        register_fs_type(
            b"saltyfs",
            &raw const SALTYFS_VFSOPS,
            &raw const SALTYFS_VOPS,
        )
    }
}
