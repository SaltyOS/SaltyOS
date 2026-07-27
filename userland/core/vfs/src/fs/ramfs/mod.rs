// SPDX-License-Identifier: GPL-2.0-only
//
//! ramfs — in-memory writable filesystem.
//!
//! Synthetic backend with no daemon — every entry runs synchronously
//! on the owner thread. Per-mount state owns three pools (vnode-data,
//! writable block chains, symlink targets) plus a dirent array hung
//! off each directory vnode. The arena that holds the live `Vnode`
//! slots is the central `VfsState.vnodes`; this module only manages
//! the backend-private side.
//!
//! Module layout:
//!
//! - [`types`]   — `Dirent`, `RamfsVnodeData`, `RamfsMountData`.
//! - [`pool`]    — per-mount pool allocators + chain / dirent helpers.
//! - [`vfsops`]  — `VfsOps` (mount, unmount, root, vget, statfs, sync).
//! - [`vops`]    — `VopVector` (lookup, create, read, write, ...).

pub(crate) mod pool;
pub(crate) mod types;
mod vfsops;
mod vops;

use crate::core::vop::{
    DATA_OPS_DEFAULT, META_OPS_DEFAULT, VfsOps, VopDataOps, VopMetaOps, VopVector,
};

// =========================================================================
// Static dispatch tables
// =========================================================================

/// Ramfs vnode operation dispatch table.
pub(crate) static RAMFS_VOPS: VopVector = VopVector {
    meta: VopMetaOps {
        lookup: vops::ramfs_lookup,
        lookup_ci: vops::ramfs_lookup_ci,
        create: vops::ramfs_create,
        mkdir: vops::ramfs_mkdir,
        symlink: vops::ramfs_symlink,
        mkfifo: crate::core::vop::META_OPS_DEFAULT.mkfifo,
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
        data_size: vops::ramfs_data_size,
        inactive: vops::ramfs_inactive,
    },
    data: VopDataOps {
        read: vops::ramfs_read,
        write: vops::ramfs_write,
        writeback: vops::ramfs_write,
        fsync: vops::ramfs_fsync,
        readdir: vops::ramfs_readdir,
        statfs: vops::ramfs_statfs,
        getxattr: DATA_OPS_DEFAULT.getxattr,
        setxattr: DATA_OPS_DEFAULT.setxattr,
        listxattr: DATA_OPS_DEFAULT.listxattr,
        removexattr: DATA_OPS_DEFAULT.removexattr,
        ioctl: DATA_OPS_DEFAULT.ioctl,
        mmap_get_page: DATA_OPS_DEFAULT.mmap_get_page,
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

// Suppress the META_OPS_DEFAULT import warning while only the
// override fields above are referenced — kept available for
// future ramfs lookup_ci customisation.
#[allow(dead_code)]
const _META_OPS_DEFAULT_REF: &VopMetaOps = &META_OPS_DEFAULT;
