// SPDX-License-Identifier: GPL-2.0-only
//
//! tmpfs — in-memory filesystem with size and inode quotas.
//!
//! Independent reimplementation from ramfs (no read-only path, no
//! initrd projection) plus quota accounting on every mutation.
//! `size=NNN` and `nr_inodes=NNN` mount options seed the quota
//! caps (`max_bytes` / `max_inodes`); 0 means unlimited.
//!
//! Module layout:
//!
//! - [`types`]   — `Dirent`, `TmpfsVnodeData`, `TmpfsMountData`.
//! - [`pool`]    — per-mount pool allocators, chain helpers, quota
//!                accounting (`check_bytes` / `account_bytes_*` /
//!                `check_inodes` / `account_inode_*`).
//! - [`vfsops`]  — `VfsOps`.
//! - [`vops`]    — `VopVector`.

pub(crate) mod pool;
pub(crate) mod types;
mod vfsops;
mod vops;

use crate::core::vop::{DATA_OPS_DEFAULT, VfsOps, VopDataOps, VopMetaOps, VopVector};

/// Tmpfs vnode operation dispatch table.
pub(crate) static TMPFS_VOPS: VopVector = VopVector {
    meta: VopMetaOps {
        lookup: vops::tmpfs_lookup,
        lookup_ci: vops::tmpfs_lookup_ci,
        create: vops::tmpfs_create,
        mkdir: vops::tmpfs_mkdir,
        symlink: vops::tmpfs_symlink,
        mkfifo: crate::core::vop::META_OPS_DEFAULT.mkfifo,
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
        data_size: vops::tmpfs_data_size,
        inactive: vops::tmpfs_inactive,
    },
    data: VopDataOps {
        read: vops::tmpfs_read,
        write: vops::tmpfs_write,
        writeback: vops::tmpfs_write,
        fsync: vops::tmpfs_fsync,
        readdir: vops::tmpfs_readdir,
        statfs: vops::tmpfs_statfs,
        getxattr: DATA_OPS_DEFAULT.getxattr,
        setxattr: DATA_OPS_DEFAULT.setxattr,
        listxattr: DATA_OPS_DEFAULT.listxattr,
        removexattr: DATA_OPS_DEFAULT.removexattr,
        ioctl: DATA_OPS_DEFAULT.ioctl,
        mmap_get_page: DATA_OPS_DEFAULT.mmap_get_page,
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
