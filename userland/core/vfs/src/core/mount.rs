// SPDX-License-Identifier: GPL-2.0-only
//
//! `Mount` — in-memory record of an active mount point. Carries
//! the mount-instance identity, the backend session that drives
//! it, the cover/covered link to the parent mount tree, and a
//! reference counter so unmount tears down once every vnode under
//! the mount has dropped.

use crate::arena::handle::Handle;
use crate::core::identity::{FsInstanceId, VnodeKey};
use crate::core::vnode::Vnode;

/// Mount-instance kind discriminator. Identifies which backend
/// drives this mount; session-backed drivers store their live
/// transport in `VfsState.backend_sessions`, while in-memory
/// synthetic filesystems keep their state in `Mount::data`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MountKind {
    /// Slot has not been populated yet.
    Empty = 0,
    /// Bootstrap initrd-backed read-only ramfs (vfs's own VAS).
    Initrd = 1,
    /// In-memory writable ramfs.
    Ramfs = 2,
    /// In-memory tmpfs (ramfs + sticky bits + size accounting).
    Tmpfs = 3,
    /// `/dev` synthetic device tree.
    Devfs = 4,
    /// `/proc` synthetic process tree.
    Procfs = 5,
    /// `/sys/sysctl` synthetic sysctl tree.
    Sysctlfs = 6,
    /// Anonymous-pipe instance (pipe(2) / pipefd hosts).
    Pipefs = 7,
    /// SaltyFS daemon (the on-disk filesystem server).
    SaltyFs = 8,
    /// Inet socket backend (smoltcp via netsrv). The mount node
    /// represents the network domain — `socket(AF_INET, ...)` and
    /// `socket(AF_INET6, ...)` route every operation through this
    /// mount's `BackendSessionSlot`.
    Inet = 9,
    /// Pseudo-terminal backend (posix_ttysrv). The mount node is
    /// typically `/dev/pts`; `openpty` / `pty open` on `/dev/ptmx`
    /// + `pts/N` route through this mount.
    Pty = 10,
    /// Framebuffer backend (dispdrv). The mount node is typically
    /// `/dev/fb` or `/dev/fb0`.
    Fb = 11,
}

impl MountKind {
    pub(crate) fn from_wire(raw: u8) -> Option<Self> {
        match raw {
            x if x == Self::Initrd as u8 => Some(Self::Initrd),
            x if x == Self::Ramfs as u8 => Some(Self::Ramfs),
            x if x == Self::Tmpfs as u8 => Some(Self::Tmpfs),
            x if x == Self::Devfs as u8 => Some(Self::Devfs),
            x if x == Self::Procfs as u8 => Some(Self::Procfs),
            x if x == Self::Sysctlfs as u8 => Some(Self::Sysctlfs),
            x if x == Self::Pipefs as u8 => Some(Self::Pipefs),
            x if x == Self::SaltyFs as u8 => Some(Self::SaltyFs),
            x if x == Self::Inet as u8 => Some(Self::Inet),
            x if x == Self::Pty as u8 => Some(Self::Pty),
            x if x == Self::Fb as u8 => Some(Self::Fb),
            _ => None,
        }
    }

    /// Canonical filesystem-type string for this mount kind, as
    /// surfaced to `getmntinfo(3)` / `getmntent(3)` callers through
    /// `VFS_MOUNT_LIST`. This is the authoritative source — it does
    /// not depend on the backend's `statfs` (service backends such
    /// as Inet/Pty/Fb have no working `statfs`).
    pub(crate) fn as_fs_name(&self) -> &'static [u8] {
        match self {
            Self::Empty => b"",
            Self::Initrd => b"initrd",
            Self::Ramfs => b"ramfs",
            Self::Tmpfs => b"tmpfs",
            Self::Devfs => b"devfs",
            Self::Procfs => b"procfs",
            Self::Sysctlfs => b"sysctlfs",
            Self::Pipefs => b"pipefs",
            Self::SaltyFs => b"saltyfs",
            Self::Inet => b"inet",
            Self::Pty => b"pty",
            Self::Fb => b"fb",
        }
    }
}

/// Maximum bytes of the absolute mount-point path stored on a
/// `Mount`. Matches the `VFS_MOUNT_LIST` wire field width
/// (`TronaMountInfo.mount_path`); longer paths are truncated at
/// store time.
pub(crate) const MOUNT_PATH_MAX: usize = 64;

/// Mount record. One per live mount point.
#[repr(C)]
pub(crate) struct Mount {
    pub kind: MountKind,
    /// Slot index into `VfsState.backend_sessions` for the backend
    /// driving this mount (`u32::MAX` for synthetic in-memory
    /// mounts that have no backend session).
    pub backend_session_idx: u32,
    /// `fs_instance_id` shared with the backend session — survives
    /// remount cycles via the session's `live_gen` advance.
    pub fs_instance_id: FsInstanceId,
    /// Root vnode of this mount.
    pub root: Handle<Vnode>,
    /// Identity of the vnode that this mount covers (the mount
    /// point in the parent mount tree). Stored as a key so it
    /// survives parent-vnode arena slot recycling.
    pub covered_key: VnodeKey,
    /// Backend-specific per-mount payload pointer (type-erased).
    /// Each filesystem client owns the concrete type behind this
    /// pointer.
    pub data: *mut u8,
    /// Pointer to the backend's `VfsOps` (mount-level operations
    /// table). Used for `vget` / `statfs` / `sync` / `unmount`.
    pub vfsops: *const crate::core::vop::VfsOps,
    /// Number of vnodes in `VfsState.vnodes` whose `mount` field
    /// points at this mount. Reaches 0 just before unmount tears
    /// down the backend session.
    pub vnode_refcount: u32,
    /// Mount flags applied at `mount(2)` time and replaceable via
    /// `remount`. Canonical `MNT_*` wire form in the low 32 bits
    /// (`trona_protocol::posix::MNT_RDONLY` etc.) plus
    /// `VFS_MOUNT_FLAG_CASEFOLD` at bit 40. basaltc lowers Linux
    /// `MS_*` into this form before the `VFS_MOUNT` request; boot
    /// mounts set the same `MNT_*` bits directly. Backends consult
    /// this on each entry to enforce the policy.
    pub mount_flags: u64,
    /// Case-fold policy for component lookup against this mount.
    ///
    /// Stored on the mount, not on the walker. The namei walker
    /// reads this on every component lookup; a mount cross during
    /// the walk picks up the new mount's policy at the cross-mount
    /// step, no walker state transfer needed.
    ///
    /// Defaults to [`CaseFoldPolicy::Sensitive`]. Filesystem
    /// clients that emulate case-insensitive preserving storage
    /// override it when they instantiate the mount.
    pub case_fold: crate::ops::CaseFoldPolicy,
    /// Absolute mount-point path (`f_mntonname`), captured at mount
    /// time. The mount tree carries no vnode→path reverse link, so
    /// `VFS_MOUNT_LIST` reports the path that was recorded here when
    /// the mount was created (boot pseudo-mounts and the root know
    /// their path internally; runtime mounts receive it on the
    /// `VFS_MOUNT` wire). Only the first `mount_path_len` bytes are
    /// valid.
    pub mount_path: [u8; MOUNT_PATH_MAX],
    /// Valid byte count in `mount_path`.
    pub mount_path_len: u8,
}

impl Mount {
    pub(crate) const EMPTY: Self = Self {
        kind: MountKind::Empty,
        backend_session_idx: u32::MAX,
        fs_instance_id: FsInstanceId::INVALID,
        root: Handle::INVALID,
        covered_key: VnodeKey::NONE,
        data: ::core::ptr::null_mut(),
        vfsops: ::core::ptr::null(),
        vnode_refcount: 0,
        mount_flags: 0,
        case_fold: crate::ops::CaseFoldPolicy::Sensitive,
        mount_path: [0; MOUNT_PATH_MAX],
        mount_path_len: 0,
    };

    /// Record the absolute mount-point path, truncating to
    /// [`MOUNT_PATH_MAX`].
    pub(crate) fn set_mount_path(&mut self, path: &[u8]) {
        let n = path.len().min(MOUNT_PATH_MAX);
        self.mount_path[..n].copy_from_slice(&path[..n]);
        self.mount_path_len = n as u8;
    }

    /// The valid prefix of [`Mount::mount_path`].
    pub(crate) fn mount_path_slice(&self) -> &[u8] {
        &self.mount_path[..self.mount_path_len as usize]
    }
}

pub(crate) type MountHandle = Handle<Mount>;
