// SPDX-License-Identifier: GPL-2.0-only
//! Mount — an instance of a filesystem mounted in the namespace tree.
//!
//! Mounts carry the structural links needed for mount grafting and root
//! transitions: parent mount, covered vnode, root vnode, filesystem type,
//! and the original mount path used by bootstrap and introspection.

use crate::arena::Handle;

use super::cached_ref::CachedRef;
use super::identity::{FsInstanceId, VnodeKey};

/// Handle-based mount identity.
pub(crate) type MountHandle = Handle<Mount>;
/// Forward import for mount-owned vnode links.
pub(crate) type VnodeHandle = Handle<super::vnode::Vnode>;

pub(crate) const MOUNT_FS_TYPE_MAX: usize = 16;
pub(crate) const MOUNT_PATH_MAX: usize = 64;
pub(crate) const MOUNT_OPTS_MAX: usize = 128;
pub(crate) const MOUNT_BACKEND_NONE: u8 = 0;
pub(crate) const MOUNT_BACKEND_BOOTFS: u8 = 1;
pub(crate) const MOUNT_BACKEND_TMPFS: u8 = 2;
pub(crate) const MOUNT_BACKEND_DEVFS: u8 = 3;
pub(crate) const MOUNT_BACKEND_PIPEFS: u8 = 4;
pub(crate) const MOUNT_BACKEND_PROCFS: u8 = 5;
pub(crate) const MOUNT_BACKEND_SALTYFS: u8 = 6;
pub(crate) const MOUNT_BACKEND_SYSCTLFS: u8 = 7;
pub(crate) const MNT_RDONLY: u32 = 1 << 0;
pub(crate) const MNT_NOSUID: u32 = 1 << 1;
pub(crate) const MNT_NOEXEC: u32 = 1 << 2;
pub(crate) const MNT_NODEV: u32 = 1 << 3;
pub(crate) const MNT_NOSYMFOLLOW: u32 = 1 << 4;
pub(crate) const MNT_BIND: u32 = 1 << 8;
pub(crate) const MNT_RBIND: u32 = 1 << 9;
/// POSIX-only mount — hidden from Win32 pathwalk.
pub(crate) const MNT_POSIX_ONLY: u32 = 1 << 10;
/// Win32-only mount — hidden from POSIX pathwalk.
pub(crate) const MNT_WIN32_ONLY: u32 = 1 << 11;
/// Case-insensitive lookup for this mount. Generic across personalities;
/// the option tokens `nocase` (CIFS/FAT idiom) and `casefold` (Linux
/// ext4 idiom) both set this bit. Backends that do not implement
/// case-folded lookup ignore the flag.
pub(crate) const MNT_CASEFOLD: u32 = 1 << 12;
/// Skip atime updates on read. Backends honor this opportunistically;
/// mount-side filtering happens regardless of backend support.
pub(crate) const MNT_NOATIME: u32 = 1 << 13;

#[repr(C)]
pub(crate) struct Mount {
    /// Local mount id, useful for stable listing order.
    pub(crate) id: u16,
    /// Typed backend kind for this mount instance.
    pub(crate) backend_kind: u8,
    _pad0: [u8; 1],
    /// Mount flags (`ro`, `nosuid`, bind, detach, ...).
    pub(crate) flags: u32,
    /// Stable mount identity that survives slot recycling.
    pub(crate) fs_instance_id: FsInstanceId,

    /// Filesystem-level dispatch anchor.
    pub(crate) vfsops: *const (),
    /// Default vnode dispatch anchor for nodes belonging to this mount.
    pub(crate) vops: *const (),

    /// Root vnode of this filesystem instance.
    pub(crate) root_vnode: VnodeHandle,
    /// Covered vnode in the parent filesystem, if this is not the root mount.
    pub(crate) covered: CachedRef<VnodeKey, VnodeHandle>,
    /// Parent mount in the namespace tree.
    pub(crate) parent: CachedRef<FsInstanceId, MountHandle>,

    /// Backend-private mount data.
    pub(crate) data: *mut u8,

    /// Filesystem type name ("ramfs", "devfs", "saltyfs", ...).
    pub(crate) fs_type_name: [u8; MOUNT_FS_TYPE_MAX],
    pub(crate) fs_type_name_len: u8,
    _pad1: [u8; 7],

    /// Canonical mount path recorded for scaffold management and mount
    /// listing. Keeping the original path matters for `pivot_root`
    /// because child pseudo-filesystems are reattached by mountpoint.
    pub(crate) mount_path: [u8; MOUNT_PATH_MAX],
    pub(crate) mount_path_len: u8,
    _pad2: [u8; 7],

    /// Raw mount option string as passed to `VFS_MOUNT` /
    /// `VFS_REMOUNT`. Backends parse this themselves; the field is
    /// retained so introspection (`getmntinfo` / `getmntent`) can
    /// surface the canonical option list to userspace.
    pub(crate) opts: [u8; MOUNT_OPTS_MAX],
    pub(crate) opts_len: u8,
    _pad3: [u8; 7],
}

impl Mount {
    /// Bootstrap root mount backing the initial namespace.
    pub(crate) fn new_boot_root(fs_instance_id: FsInstanceId, root_vnode: VnodeHandle) -> Self {
        let mut mount = Mount {
            id: 1,
            backend_kind: MOUNT_BACKEND_BOOTFS,
            _pad0: [0; 1],
            flags: 0,
            fs_instance_id,
            vfsops: core::ptr::null(),
            vops: core::ptr::null(),
            root_vnode,
            covered: CachedRef::<VnodeKey, VnodeHandle>::INVALID,
            parent: CachedRef::<FsInstanceId, MountHandle>::INVALID,
            data: core::ptr::null_mut(),
            fs_type_name: [0; MOUNT_FS_TYPE_MAX],
            fs_type_name_len: 6,
            _pad1: [0; 7],
            mount_path: [0; MOUNT_PATH_MAX],
            mount_path_len: 1,
            _pad2: [0; 7],
            opts: [0; MOUNT_OPTS_MAX],
            opts_len: 0,
            _pad3: [0; 7],
        };
        mount.fs_type_name[..6].copy_from_slice(b"bootfs");
        mount.mount_path[0] = b'/';
        mount
    }

    /// Detached structural mount prepared before grafting into the tree.
    pub(crate) fn new_structural(
        id: u16,
        flags: u32,
        fs_instance_id: FsInstanceId,
        root_vnode: VnodeHandle,
        fs_type_name: &[u8],
        mount_path: &[u8],
    ) -> Self {
        let mut mount = Mount {
            id,
            backend_kind: MOUNT_BACKEND_NONE,
            _pad0: [0; 1],
            flags,
            fs_instance_id,
            vfsops: core::ptr::null(),
            vops: core::ptr::null(),
            root_vnode,
            covered: CachedRef::<VnodeKey, VnodeHandle>::INVALID,
            parent: CachedRef::<FsInstanceId, MountHandle>::INVALID,
            data: core::ptr::null_mut(),
            fs_type_name: [0; MOUNT_FS_TYPE_MAX],
            fs_type_name_len: 0,
            _pad1: [0; 7],
            mount_path: [0; MOUNT_PATH_MAX],
            mount_path_len: 0,
            _pad2: [0; 7],
            opts: [0; MOUNT_OPTS_MAX],
            opts_len: 0,
            _pad3: [0; 7],
        };
        let _ = mount.set_fs_type_name(fs_type_name);
        let _ = mount.set_mount_path(mount_path);
        mount
    }

    /// Update the filesystem type name used for introspection.
    pub(crate) fn set_fs_type_name(&mut self, fs_type_name: &[u8]) -> bool {
        if fs_type_name.len() > MOUNT_FS_TYPE_MAX {
            return false;
        }
        self.fs_type_name = [0; MOUNT_FS_TYPE_MAX];
        self.fs_type_name[..fs_type_name.len()].copy_from_slice(fs_type_name);
        self.fs_type_name_len = fs_type_name.len() as u8;
        true
    }

    /// Update the canonical mount path used for structural reattachment.
    pub(crate) fn set_mount_path(&mut self, path: &[u8]) -> bool {
        if path.len() > MOUNT_PATH_MAX {
            return false;
        }
        self.mount_path = [0; MOUNT_PATH_MAX];
        self.mount_path[..path.len()].copy_from_slice(path);
        self.mount_path_len = path.len() as u8;
        true
    }

    /// Replace the canonical mount option string. Truncates silently if
    /// `opts.len() > MOUNT_OPTS_MAX` so callers never lose mounts over
    /// an over-long option list — backends already drop unknown
    /// tokens, so callers see consistent behavior.
    pub(crate) fn set_opts(&mut self, opts: &[u8]) {
        let len = opts.len().min(MOUNT_OPTS_MAX);
        self.opts = [0; MOUNT_OPTS_MAX];
        self.opts[..len].copy_from_slice(&opts[..len]);
        self.opts_len = len as u8;
    }

    pub(crate) fn opts_slice(&self) -> &[u8] {
        &self.opts[..self.opts_len as usize]
    }
}
