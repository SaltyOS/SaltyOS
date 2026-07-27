// SPDX-License-Identifier: GPL-2.0-only
//
//! VFS client for the SaltyFS daemon. Drives `BACKEND_*` calls
//! against the daemon's per-mount-instance session, packs /
//! unpacks [`SaltyfsOpKind`] payloads on PendingOps, and owns
//! the SHM handshake for bulk readdir / xattr transfers.
//!
//! # Module layout
//!
//! - [`types`] — `SaltyfsMountData`, `SaltyfsVnodeData`
//! - [`op_kind`] — `SaltyfsOpKind` packing into `PendingKindPayload`
//! - [`feature`] — incompat / casefold / xattr feature flags
//! - [`pool`] — per-mount vdata cache
//! - [`rpc`] — read-only RPC issue / parse helpers (lookup,
//!   stat, readlink, read, readdir, getinfo)
//! - [`mutate_rpc`] — mutating RPC issue / parse (create,
//!   mkdir, symlink, unlink, rmdir, link, rename, setattr,
//!   truncate, write)
//! - [`xattr_rpc`] — extended-attribute RPC (getxattr / setxattr
//!   / listxattr / removexattr)
//! - [`readdir`] — SHM-batch readdir helpers
//! - [`deferred`] — wait-queue drain + xattr SHM ownership
//! - [`completion`] — backend reply router
//! - [`vops`] — `VopMetaOps` + `VopDataOps` impl
//! - [`vfsops`] — `VfsOps` impl + mount finalize / teardown

pub(crate) mod completion;
pub(crate) mod deferred;
pub(crate) mod feature;
pub(crate) mod mutate_rpc;
pub(crate) mod op_kind;
pub(crate) mod pool;
pub(crate) mod readdir;
pub(crate) mod rpc;
pub(crate) mod types;
pub(crate) mod vfsops;
pub(crate) mod vops;
pub(crate) mod xattr_rpc;

pub(crate) use readdir::READDIR_ENTRY_BYTES;
pub(crate) use readdir::READDIR_NAME_MAX;
pub(crate) use readdir::dir_type_to_dtype as readdir_dir_type_to_dtype;
pub(crate) use readdir::dtype_to_vtype as readdir_dtype_to_vtype;
pub(crate) use readdir::mode_to_dtype as readdir_mode_to_dtype;
pub(crate) use rpc::saltyfs_ipc_read_parse;
pub(crate) use rpc::saltyfs_ipc_readdir_parse;
pub(crate) use rpc::saltyfs_ipc_readlink_parse;
pub(crate) use vfsops::SALTYFS_VFSOPS;
pub(crate) use xattr_rpc::saltyfs_ipc_listxattr_parse;
pub(crate) use xattr_rpc::saltyfs_ipc_xattr_get_parse;

use crate::core::vop::{META_OPS_DEFAULT, VopDataOps, VopMetaOps, VopVector};

/// SaltyFS VopVector. One static instance pinned on every saltyfs
/// vnode (`Vnode.ops`); the dispatch layer routes through these
/// entries instead of branching on `Mount.kind`.
pub(crate) static SALTYFS_VOPS: VopVector = VopVector {
    meta: VopMetaOps {
        lookup: vops::saltyfs_lookup,
        lookup_ci: vops::saltyfs_lookup,
        create: vops::saltyfs_create,
        mkdir: vops::saltyfs_mkdir,
        symlink: vops::saltyfs_symlink,
        mkfifo: crate::core::vop::META_OPS_DEFAULT.mkfifo,
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
        data_size: vops::saltyfs_data_size,
        inactive: vops::saltyfs_inactive,
    },
    data: VopDataOps {
        read: vops::saltyfs_read,
        write: vops::saltyfs_write,
        writeback: vops::saltyfs_writeback,
        fsync: vops::saltyfs_fsync,
        readdir: vops::saltyfs_readdir,
        getxattr: vops::saltyfs_getxattr,
        setxattr: vops::saltyfs_setxattr,
        listxattr: vops::saltyfs_listxattr,
        removexattr: vops::saltyfs_removexattr,
        ioctl: vops::saltyfs_ioctl,
        mmap_get_page: vops::saltyfs_mmap_get_page,
        statfs: vops::saltyfs_statfs,
        // Mode hints copied from the default — saltyfs reads /
        // writes / readdirs run on the owner thread today; a
        // future worker-pool migration flips these per-op.
    },
};

// Trigger META_OPS_DEFAULT into the link map so its symbols stay
// available for backends that derive their VopMetaOps via
// `..META_OPS_DEFAULT` struct update (ramfs / tmpfs / pipefs etc.).
#[allow(dead_code)]
const _: &VopMetaOps = &META_OPS_DEFAULT;
