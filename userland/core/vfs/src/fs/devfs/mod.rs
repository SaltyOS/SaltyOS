// SPDX-License-Identifier: GPL-2.0-only
//! devfs — device filesystem backed by a static registration table.
//!
//! devfs presents character-device nodes (`/dev/console`, `/dev/null`,
//! `/dev/zero`, `/dev/urandom`, `/dev/fb0`, `/dev/ptmx`, `/dev/tty`) and a dynamic
//! `pts/` subdirectory for allocated PTY slaves.
//!
//! The filesystem is read-only in terms of namespace mutation: `create`,
//! `mkdir`, `unlink`, `rmdir`, `rename` all return `NotSupported`. The
//! `open` / `read` / `write` ops dispatch per-device I/O (serial IPC for
//! console, CSPRNG for urandom, posix_ttysrv IPC for PTY, etc.).

mod vfsops;
mod vops;

use crate::vfs_core::error::VfsResult;
use crate::vfs_core::vfs::{register_fs_type, VfsOps};
use crate::vfs_core::vnode::VnodeHandle;
use crate::vfs_core::vop::VopVector;

// =========================================================================
// DevKind — device type discriminator
// =========================================================================

/// Identifies the device backing a devfs vnode.
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
    /// The `/dev/pts` directory itself (synthetic container).
    PtsDir = 8,
}

// =========================================================================
// Static device registration table
// =========================================================================

/// One entry in the static device registration table.
pub(crate) struct DevfsRegistration {
    pub(crate) name: &'static [u8],
    pub(crate) kind: DevKind,
    pub(crate) mode: u32,
}

/// Static table of device nodes that devfs exposes at the top level.
/// The `pts` subdirectory is handled specially in `lookup` / `readdir`.
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

/// Backend-private data hung off `Vnode.data` for devfs vnodes.
#[repr(C)]
pub(crate) struct DevfsVnodeData {
    pub(crate) kind: DevKind,
    /// PTY slave index for `PtySlave` nodes; unused otherwise.
    pub(crate) sub_id: u32,
    /// POSIX mode bits (type + permission).
    pub(crate) mode: u32,
}

// =========================================================================
// DevfsMountData — per-mount backend data
// =========================================================================

/// Maximum number of vnodes managed by a single devfs mount.
///
/// `DEVFS_REGISTRATIONS.len()` static devices + 1 root dir + 1 pts dir
/// + dynamic PTY slave entries.
pub(super) const MAX_DEVFS_VNODES: usize = 32;

/// Per-mount state for devfs.
#[repr(C)]
pub(crate) struct DevfsMountData {
    /// Parallel array: arena handles for tracked vnodes.
    pub(crate) vnode_handles: [VnodeHandle; MAX_DEVFS_VNODES],
    /// Parallel array: vnode ids for tracked vnodes.
    pub(crate) vnode_ids: [u64; MAX_DEVFS_VNODES],
    /// Parallel array of vnode-private data.
    pub(crate) vdata: [DevfsVnodeData; MAX_DEVFS_VNODES],
    /// Number of vnodes currently populated (next allocation index).
    pub(crate) count: usize,
}

// DevfsMountData is allocated via map_anon + write_bytes (zero-init).
// VnodeHandle zero = Handle { slot: 0, gen: 0 } which passes is_valid()
// but the count field gates iteration so only populated entries are accessed.

// =========================================================================
// Vdata allocator and vnode tracker
// =========================================================================

/// Allocate a vnode-data slot from the devfs mount data pool.
///
/// Returns a pointer to the allocated `DevfsVnodeData`, or null if
/// the pool is full. The caller initializes the slot.
///
/// # Safety
///
/// `mount_data` must point to a valid `DevfsMountData`.
pub(super) unsafe fn alloc_vdata(mount_data: *mut u8) -> *mut DevfsVnodeData {
    unsafe {
        let md = mount_data as *mut DevfsMountData;
        if (*md).count >= MAX_DEVFS_VNODES {
            return core::ptr::null_mut();
        }
        let idx = (*md).count;
        // count is incremented by record_vnode after handle is known.
        &raw mut (*md).vdata[idx]
    }
}

/// Record a vnode handle and id in the parallel tracking arrays.
///
/// Must be called after `alloc_vdata` for the same slot index (count).
///
/// # Safety
///
/// `mount_data` must point to a valid `DevfsMountData`. Must be called
/// exactly once per `alloc_vdata` call, before another `alloc_vdata`.
pub(super) unsafe fn record_vnode(mount_data: *mut u8, vh: VnodeHandle, id: u64) {
    unsafe {
        let md = mount_data as *mut DevfsMountData;
        let idx = (*md).count;
        (*md).vnode_handles[idx] = vh;
        (*md).vnode_ids[idx] = id;
        (*md).count += 1;
    }
}

// =========================================================================
// Static VfsOps / VopVector
// =========================================================================

pub(crate) static DEVFS_VFSOPS: VfsOps = vfsops::DEVFS_VFSOPS;
pub(crate) static DEVFS_VOPS: VopVector = vops::DEVFS_VOPS;

// =========================================================================
// Registration
// =========================================================================

/// Register the `devfs` filesystem type. Called during VFS bootstrap Stage 2.
pub(crate) unsafe fn register() -> VfsResult<()> {
    unsafe {
        register_fs_type(
            b"devfs",
            &raw const DEVFS_VFSOPS,
            &raw const DEVFS_VOPS,
        )
    }
}
