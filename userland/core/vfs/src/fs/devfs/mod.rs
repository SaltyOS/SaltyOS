// SPDX-License-Identifier: GPL-2.0-only
//
//! devfs — synthetic device filesystem.
//!
//! Presents the canonical `/dev/console`, `/dev/null`, `/dev/zero`,
//! `/dev/urandom`, `/dev/fb0`, `/dev/ptmx`, `/dev/tty` device nodes
//! plus a synthetic `pts/` subdirectory for posix_ttysrv-allocated
//! PTY slaves.
//!
//! Read-only namespace — `create` / `mkdir` / `unlink` / `rmdir`
//! / `rename` all return `NotSup`. The `read` / `write` / `ioctl`
//! ops dispatch per-device IO (serial IPC for the console, `KernelRng`
//! for `urandom`, posix_ttysrv IPC for PTY paths once that lands).

mod vfsops;
mod vops;

use crate::core::vnode::VnodeHandle;
use crate::core::vop::{
    DATA_OPS_DEFAULT, META_OPS_DEFAULT, VfsOps, VopDataOps, VopMetaOps, VopVector,
};

// =========================================================================
// DevKind — device type discriminator
// =========================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DevKind {
    Console = 0,
    Null = 1,
    Zero = 2,
    Fb0 = 3,
    Urandom = 4,
    Ptmx = 5,
    /// The calling client's controlling terminal (`/dev/tty`).
    Tty = 6,
    /// A specific PTY slave device (`/dev/pts/N`).
    PtySlave = 7,
    /// The `/dev/pts` directory itself.
    PtsDir = 8,
}

// =========================================================================
// Static device registration table
// =========================================================================

pub(crate) struct DevfsRegistration {
    pub(crate) name: &'static [u8],
    pub(crate) kind: DevKind,
    pub(crate) mode: u32,
}

pub(crate) static DEVFS_REGISTRATIONS: &[DevfsRegistration] = &[
    DevfsRegistration {
        name: b"console",
        kind: DevKind::Console,
        mode: 0o020666,
    },
    DevfsRegistration {
        name: b"null",
        kind: DevKind::Null,
        mode: 0o020666,
    },
    DevfsRegistration {
        name: b"zero",
        kind: DevKind::Zero,
        mode: 0o020666,
    },
    DevfsRegistration {
        name: b"fb0",
        kind: DevKind::Fb0,
        mode: 0o020660,
    },
    DevfsRegistration {
        name: b"urandom",
        kind: DevKind::Urandom,
        mode: 0o020666,
    },
    DevfsRegistration {
        name: b"ptmx",
        kind: DevKind::Ptmx,
        mode: 0o020666,
    },
    DevfsRegistration {
        name: b"tty",
        kind: DevKind::Tty,
        mode: 0o020666,
    },
];

// =========================================================================
// DevfsVnodeData — per-vnode backend data
// =========================================================================

#[repr(C)]
pub(crate) struct DevfsVnodeData {
    pub(crate) kind: DevKind,
    /// PTY slave index for `PtySlave` nodes; unused otherwise.
    pub(crate) sub_id: u32,
    /// POSIX mode bits.
    pub(crate) mode: u32,
    /// PTY generation captured at lookup; passed back on slave
    /// open so posix_ttysrv can reject opens against a slot that
    /// has been recycled. Future PTY-routing path consumes this.
    pub(crate) generation: u32,
}

// =========================================================================
// DevfsMountData — per-mount backend data
// =========================================================================

/// `DEVFS_REGISTRATIONS.len()` static devices + 1 root + 1 pts
/// dir + dynamic PTY slave entries.
pub(super) const MAX_DEVFS_VNODES: usize = 32;

#[repr(C)]
pub(crate) struct DevfsMountData {
    pub(crate) vnode_handles: [VnodeHandle; MAX_DEVFS_VNODES],
    pub(crate) vnode_ids: [u64; MAX_DEVFS_VNODES],
    pub(crate) vdata: [DevfsVnodeData; MAX_DEVFS_VNODES],
    pub(crate) count: usize,
}

// =========================================================================
// Vdata allocator
// =========================================================================

pub(super) unsafe fn alloc_vdata(mount_data: *mut u8) -> *mut DevfsVnodeData {
    unsafe {
        let md = mount_data as *mut DevfsMountData;
        if (*md).count >= MAX_DEVFS_VNODES {
            return ::core::ptr::null_mut();
        }
        let idx = (*md).count;
        // record_vnode bumps `count`; at this point we hand out
        // the slot pointer for the caller to fill.
        &raw mut (*md).vdata[idx]
    }
}

pub(super) unsafe fn record_vnode(mount_data: *mut u8, vnode_h: VnodeHandle, id: u64) {
    unsafe {
        let md = mount_data as *mut DevfsMountData;
        let idx = (*md).count;
        (*md).vnode_handles[idx] = vnode_h;
        (*md).vnode_ids[idx] = id;
        (*md).count = idx + 1;
    }
}

// =========================================================================
// Static dispatch tables
// =========================================================================

pub(crate) static DEVFS_VOPS: VopVector = VopVector {
    meta: VopMetaOps {
        lookup: vops::devfs_lookup,
        lookup_ci: vops::devfs_lookup,
        create: META_OPS_DEFAULT.create,
        mkdir: META_OPS_DEFAULT.mkdir,
        symlink: META_OPS_DEFAULT.symlink,
        mkfifo: META_OPS_DEFAULT.mkfifo,
        unlink: META_OPS_DEFAULT.unlink,
        rmdir: META_OPS_DEFAULT.rmdir,
        link: META_OPS_DEFAULT.link,
        rename: META_OPS_DEFAULT.rename,
        open: vops::devfs_open,
        close: vops::devfs_close,
        getattr: vops::devfs_getattr,
        setattr: META_OPS_DEFAULT.setattr,
        access: vops::devfs_access,
        readlink: META_OPS_DEFAULT.readlink,
        truncate: META_OPS_DEFAULT.truncate,
        data_size: META_OPS_DEFAULT.data_size,
        inactive: vops::devfs_inactive,
    },
    data: VopDataOps {
        read: vops::devfs_read,
        write: vops::devfs_write,
        writeback: vops::devfs_write,
        fsync: DATA_OPS_DEFAULT.fsync,
        readdir: vops::devfs_readdir,
        statfs: vops::devfs_statfs,
        getxattr: DATA_OPS_DEFAULT.getxattr,
        setxattr: DATA_OPS_DEFAULT.setxattr,
        listxattr: DATA_OPS_DEFAULT.listxattr,
        removexattr: DATA_OPS_DEFAULT.removexattr,
        ioctl: vops::devfs_ioctl,
        mmap_get_page: DATA_OPS_DEFAULT.mmap_get_page,
    },
};

pub(crate) static DEVFS_VFSOPS: VfsOps = VfsOps {
    mount: vfsops::devfs_mount,
    unmount: vfsops::devfs_unmount,
    root: vfsops::devfs_root,
    vget: vfsops::devfs_vget,
    statfs: vfsops::devfs_statfs,
    sync: vfsops::devfs_sync,
};
