// SPDX-License-Identifier: GPL-2.0-only
//! Vnode — personality-neutral filesystem node.
//!
//! A vnode is the stable namespace anchor for one filesystem object. It
//! knows which mount owns it, which child mount covers it, and which
//! backend object identity it represents.

use crate::arena::Handle;

use super::cached_ref::CachedRef;
use super::identity::{FsInstanceId, VnodeKey};

/// Handle-based vnode identity.
pub(crate) type VnodeHandle = Handle<Vnode>;
/// Forward import for mount-owned links.
pub(crate) use super::mount::MountHandle;

/// Regular file.
pub(crate) const VT_REG: u8 = 1;
/// Directory.
pub(crate) const VT_DIR: u8 = 2;
/// Symbolic link.
pub(crate) const VT_LNK: u8 = 3;
/// Character device.
pub(crate) const VT_CHR: u8 = 4;
/// Block device.
pub(crate) const VT_BLK: u8 = 5;
/// Named pipe / FIFO.
pub(crate) const VT_FIFO: u8 = 6;
/// Socket.
pub(crate) const VT_SOCK: u8 = 7;
pub(crate) const VNODE_BACKEND_NONE: u8 = 0;
pub(crate) const VNODE_BACKEND_BOOTSTRAP: u8 = 1;
pub(crate) const VNODE_BACKEND_TMPFS: u8 = 2;
pub(crate) const VNODE_BACKEND_DEVFS: u8 = 3;
pub(crate) const VNODE_BACKEND_PIPEFS: u8 = 4;
pub(crate) const VNODE_BACKEND_PROCFS: u8 = 5;
pub(crate) const VNODE_BACKEND_SALTYFS: u8 = 6;
pub(crate) const VNODE_BACKEND_SYSCTLFS: u8 = 7;

/// Root vnode of a mount.
pub(crate) const VN_ROOT: u16 = 1 << 0;
/// Covered by a child mount.
pub(crate) const VN_COVERED: u16 = 1 << 1;
/// Invalidated by mount teardown.
pub(crate) const VN_DOOMED: u16 = 1 << 2;
/// Structural pin; cannot be reclaimed while set.
pub(crate) const VN_PINNED: u16 = 1 << 3;

#[repr(C)]
pub(crate) struct Vnode {
    /// Object type (`VT_*`).
    pub(crate) vtype: u8,
    /// Typed backend kind for this vnode.
    pub(crate) backend_kind: u8,
    _pad0: [u8; 2],
    /// Status flags (`VN_*`).
    pub(crate) flags: u16,
    _pad1: [u8; 2],
    /// POSIX mode bits (type + permission).
    pub(crate) mode: u32,

    /// Backend-defined object id.
    pub(crate) id: u64,
    /// Backend-defined incarnation / sequence.
    pub(crate) backend_seq: u32,
    /// Owner user id.
    pub(crate) uid: u32,
    /// Owner group id.
    pub(crate) gid: u32,
    /// Access time in nanoseconds since UNIX epoch.
    pub(crate) atime_ns: u64,
    /// Modification time in nanoseconds since UNIX epoch.
    pub(crate) mtime_ns: u64,
    /// File size in bytes.
    pub(crate) size: u64,
    /// Stable mount identity that owns this vnode.
    pub(crate) fs_instance_id: FsInstanceId,

    /// Owning mount as `(stable id, handle hint)`.
    pub(crate) mount: CachedRef<FsInstanceId, MountHandle>,
    /// Child mount covering this vnode, if any.
    pub(crate) covered_by: CachedRef<FsInstanceId, MountHandle>,

    /// Backend dispatch anchor for this vnode.
    pub(crate) ops: *const (),
    /// Backend-private vnode data.
    pub(crate) data: *mut u8,
    /// Generic backend-owned state handle slot.
    pub(crate) backend_ref_slot: u32,
    /// Generic backend-owned state handle epoch.
    pub(crate) backend_ref_epoch: u32,

    /// Open and link accounting.
    pub(crate) open_count: u32,
    pub(crate) nlink: u32,
    /// Structural pin count.
    pub(crate) pin_count: u16,
    _pad3: [u8; 6],
}

impl Vnode {
    /// Bootstrap root directory vnode.
    pub(crate) fn new_root_dir(fs_instance_id: FsInstanceId) -> Self {
        Vnode {
            vtype: VT_DIR,
            backend_kind: VNODE_BACKEND_BOOTSTRAP,
            _pad0: [0; 2],
            flags: VN_ROOT | VN_PINNED,
            _pad1: [0; 2],
            mode: crate::vfs_core::bootstrap::bootstrap_path_mode(b"/"),
            id: 1,
            backend_seq: 0,
            uid: 0,
            gid: 0,
            atime_ns: 0,
            mtime_ns: 0,
            size: 0,
            fs_instance_id,
            mount: CachedRef::<FsInstanceId, MountHandle>::INVALID,
            covered_by: CachedRef::<FsInstanceId, MountHandle>::INVALID,
            ops: core::ptr::null(),
            data: core::ptr::null_mut(),
            backend_ref_slot: 0,
            backend_ref_epoch: 0,
            open_count: 0,
            nlink: 1,
            pin_count: 1,
            _pad3: [0; 6],
        }
    }

    /// Root directory vnode of a mounted filesystem instance.
    pub(crate) fn new_mounted_root_dir(fs_instance_id: FsInstanceId) -> Self {
        let mut vnode = Vnode::new_root_dir(fs_instance_id);
        vnode.backend_kind = VNODE_BACKEND_NONE;
        vnode.id = 1;
        vnode
    }

    /// Bootstrap-owned directory vnode anchored under the boot root.
    pub(crate) fn new_bootstrap_dir(fs_instance_id: FsInstanceId, mount: MountHandle) -> Self {
        Vnode {
            vtype: VT_DIR,
            backend_kind: VNODE_BACKEND_BOOTSTRAP,
            _pad0: [0; 2],
            flags: 0,
            _pad1: [0; 2],
            mode: crate::vfs_core::bootstrap::bootstrap_path_mode(b"/"),
            id: 0,
            backend_seq: 0,
            uid: 0,
            gid: 0,
            atime_ns: 0,
            mtime_ns: 0,
            size: 0,
            fs_instance_id,
            mount: CachedRef::new(fs_instance_id, mount),
            covered_by: CachedRef::<FsInstanceId, MountHandle>::INVALID,
            ops: core::ptr::null(),
            data: core::ptr::null_mut(),
            backend_ref_slot: 0,
            backend_ref_epoch: 0,
            open_count: 0,
            nlink: 1,
            pin_count: 0,
            _pad3: [0; 6],
        }
    }

    /// Bootstrap-owned regular file vnode anchored under the boot root.
    pub(crate) fn new_bootstrap_file(
        fs_instance_id: FsInstanceId,
        mount: MountHandle,
        mode: u32,
    ) -> Self {
        Vnode {
            vtype: VT_REG,
            backend_kind: VNODE_BACKEND_BOOTSTRAP,
            _pad0: [0; 2],
            flags: 0,
            _pad1: [0; 2],
            mode,
            id: 0,
            backend_seq: 0,
            uid: 0,
            gid: 0,
            atime_ns: 0,
            mtime_ns: 0,
            size: 0,
            fs_instance_id,
            mount: CachedRef::new(fs_instance_id, mount),
            covered_by: CachedRef::<FsInstanceId, MountHandle>::INVALID,
            ops: core::ptr::null(),
            data: core::ptr::null_mut(),
            backend_ref_slot: 0,
            backend_ref_epoch: 0,
            open_count: 0,
            nlink: 1,
            pin_count: 0,
            _pad3: [0; 6],
        }
    }

    /// Bootstrap-owned symbolic link vnode anchored under the boot root.
    pub(crate) fn new_bootstrap_symlink(
        fs_instance_id: FsInstanceId,
        mount: MountHandle,
        mode: u32,
    ) -> Self {
        Vnode {
            vtype: VT_LNK,
            backend_kind: VNODE_BACKEND_BOOTSTRAP,
            _pad0: [0; 2],
            flags: 0,
            _pad1: [0; 2],
            mode,
            id: 0,
            backend_seq: 0,
            uid: 0,
            gid: 0,
            atime_ns: 0,
            mtime_ns: 0,
            size: 0,
            fs_instance_id,
            mount: CachedRef::new(fs_instance_id, mount),
            covered_by: CachedRef::<FsInstanceId, MountHandle>::INVALID,
            ops: core::ptr::null(),
            data: core::ptr::null_mut(),
            backend_ref_slot: 0,
            backend_ref_epoch: 0,
            open_count: 0,
            nlink: 1,
            pin_count: 0,
            _pad3: [0; 6],
        }
    }

    /// Bootstrap-owned FIFO vnode anchored under the boot root.
    pub(crate) fn new_bootstrap_fifo(
        fs_instance_id: FsInstanceId,
        mount: MountHandle,
        mode: u32,
    ) -> Self {
        Vnode {
            vtype: VT_FIFO,
            backend_kind: VNODE_BACKEND_BOOTSTRAP,
            _pad0: [0; 2],
            flags: 0,
            _pad1: [0; 2],
            mode,
            id: 0,
            backend_seq: 0,
            uid: 0,
            gid: 0,
            atime_ns: 0,
            mtime_ns: 0,
            size: 0,
            fs_instance_id,
            mount: CachedRef::new(fs_instance_id, mount),
            covered_by: CachedRef::<FsInstanceId, MountHandle>::INVALID,
            ops: core::ptr::null(),
            data: core::ptr::null_mut(),
            backend_ref_slot: 0,
            backend_ref_epoch: 0,
            open_count: 0,
            nlink: 1,
            pin_count: 0,
            _pad3: [0; 6],
        }
    }

    /// Bootstrap-owned Unix socket vnode anchored under the boot root.
    pub(crate) fn new_bootstrap_socket(
        fs_instance_id: FsInstanceId,
        mount: MountHandle,
        mode: u32,
    ) -> Self {
        Vnode {
            vtype: VT_SOCK,
            backend_kind: VNODE_BACKEND_BOOTSTRAP,
            _pad0: [0; 2],
            flags: 0,
            _pad1: [0; 2],
            mode,
            id: 0,
            backend_seq: 0,
            uid: 0,
            gid: 0,
            atime_ns: 0,
            mtime_ns: 0,
            size: 0,
            fs_instance_id,
            mount: CachedRef::new(fs_instance_id, mount),
            covered_by: CachedRef::<FsInstanceId, MountHandle>::INVALID,
            ops: core::ptr::null(),
            data: core::ptr::null_mut(),
            backend_ref_slot: 0,
            backend_ref_epoch: 0,
            open_count: 0,
            nlink: 1,
            pin_count: 0,
            _pad3: [0; 6],
        }
    }

    /// Bootstrap-owned character device vnode anchored under the boot root.
    pub(crate) fn new_bootstrap_char_device(
        fs_instance_id: FsInstanceId,
        mount: MountHandle,
        mode: u32,
        inode: u64,
        generation: u32,
    ) -> Self {
        Vnode {
            vtype: VT_CHR,
            backend_kind: VNODE_BACKEND_BOOTSTRAP,
            _pad0: [0; 2],
            flags: 0,
            _pad1: [0; 2],
            mode,
            id: inode,
            backend_seq: generation,
            uid: 0,
            gid: 0,
            atime_ns: 0,
            mtime_ns: 0,
            size: 0,
            fs_instance_id,
            mount: CachedRef::new(fs_instance_id, mount),
            covered_by: CachedRef::<FsInstanceId, MountHandle>::INVALID,
            ops: core::ptr::null(),
            data: core::ptr::null_mut(),
            backend_ref_slot: 0,
            backend_ref_epoch: 0,
            open_count: 0,
            nlink: 1,
            pin_count: 0,
            _pad3: [0; 6],
        }
    }

    #[inline]
    pub(crate) fn pin(&mut self) {
        self.pin_count = self.pin_count.saturating_add(1);
        self.flags |= VN_PINNED;
    }

    #[inline]
    pub(crate) fn unpin(&mut self) {
        self.pin_count = self.pin_count.saturating_sub(1);
        if self.pin_count == 0 {
            self.flags &= !VN_PINNED;
        }
    }

    #[inline]
    pub(crate) fn vnode_key(&self) -> VnodeKey {
        VnodeKey {
            fs_instance_id: self.fs_instance_id,
            backend_id: trona_protocol::BackendNodeId::new(self.id, self.backend_seq),
        }
    }

    #[inline]
    pub(crate) fn backend_ref<T>(&self) -> Handle<T> {
        Handle::new(self.backend_ref_slot, self.backend_ref_epoch)
    }

    #[inline]
    pub(crate) fn set_backend_ref<T>(&mut self, handle: Handle<T>) {
        self.backend_ref_slot = handle.slot();
        self.backend_ref_epoch = handle.epoch();
    }

    #[inline]
    pub(crate) fn clear_backend_ref(&mut self) {
        self.backend_ref_slot = 0;
        self.backend_ref_epoch = 0;
    }
}
