// SPDX-License-Identifier: GPL-2.0-only
//! Bootstrap namespace layout.
//!
//! The VFS boot root starts as an initramfs-style namespace that hosts the
//! FHS scaffold and pseudo-filesystem mountpoints. When the real root
//! filesystem is ready, `pivot_root` reuses these anchors instead of
//! rebuilding the tree from scratch.

use super::mount::{MNT_POSIX_ONLY, MountHandle};
use super::vnode::VnodeHandle;
use trona_posix::consts::{S_IFDIR, S_IFREG};

pub(crate) const BOOTSTRAP_NAME_MAX: usize = 128;
pub(crate) const BOOTSTRAP_ENTRY_CAP: usize = 512;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct BootstrapSeedFile {
    pub(crate) name: &'static [u8],
    pub(crate) mode: u32,
    pub(crate) content: &'static [u8],
}

/// Owner-managed bootstrap tree entry.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct BootstrapDirEntry {
    pub(crate) active: u8,
    pub(crate) name_len: u8,
    _pad0: [u8; 6],
    pub(crate) parent: VnodeHandle,
    pub(crate) vnode: VnodeHandle,
    pub(crate) name: [u8; BOOTSTRAP_NAME_MAX],
}

impl BootstrapDirEntry {
    pub(crate) const fn zeroed() -> Self {
        BootstrapDirEntry {
            active: 0,
            name_len: 0,
            _pad0: [0; 6],
            parent: VnodeHandle::INVALID,
            vnode: VnodeHandle::INVALID,
            name: [0; BOOTSTRAP_NAME_MAX],
        }
    }
}

/// Top-level bootstrap directories created under `/` before the real root
/// filesystem is grafted on `/newroot`.
pub(crate) const BOOTSTRAP_ROOT_DIRS: &[&[u8]] = &[
    b"bin",
    b"sbin",
    b"lib",
    b"usr",
    b"etc",
    b"var",
    b"tmp",
    b"dev",
    b"proc",
    b"sys",
    b"home",
    b"root",
    b"mnt",
    b"pipe",
    b"initramfs",
    b"newroot",
];

/// Pseudo-filesystem child mounts that are preserved across root swap.
pub(crate) const PIVOT_REATTACH_DIRS: &[&[u8]] = &[b"dev", b"proc", b"tmp", b"sys", b"pipe"];

/// Directories that must exist on the new root before the old root is
/// attached under `/initramfs`.
pub(crate) const POST_PIVOT_DIRS: &[&[u8]] =
    &[b"dev", b"proc", b"tmp", b"sys", b"pipe", b"initramfs"];

/// Pseudo-filesystem mounts created under the bootstrap root before the
/// real root is grafted on `/newroot`.
pub(crate) const BOOTSTRAP_PSEUDO_MOUNTS: &[(&[u8], &[u8], u32, &[u8])] = &[
    (b"/dev", b"devfs", 0, b""),
    (b"/proc", b"procfs", MNT_POSIX_ONLY, b""),
    (b"/tmp", b"tmpfs", 0, b""),
    (b"/sys", b"sysctlfs", MNT_POSIX_ONLY, b""),
    (b"/pipe", b"pipefs", 0, b""),
];

pub(crate) const BOOTSTRAP_ETC_FILES: &[BootstrapSeedFile] = &[
    BootstrapSeedFile {
        name: b"fstab",
        mode: (S_IFREG as u32) | 0o444,
        content: b"devfs /dev devfs defaults 0 0\nprocfs /proc procfs defaults 0 0\ntmpfs /tmp tmpfs defaults 0 0\nsysctlfs /sys sysctlfs defaults 0 0\npipefs /pipe pipefs defaults 0 0\n",
    },
    BootstrapSeedFile {
        name: b"passwd",
        mode: (S_IFREG as u32) | 0o644,
        content: b"root:x:0:0:root:/root:/bin/bash\n",
    },
    BootstrapSeedFile {
        name: b"shadow",
        mode: (S_IFREG as u32) | 0o600,
        content: b"root::0:0:99999:7:::\n",
    },
    BootstrapSeedFile {
        name: b"group",
        mode: (S_IFREG as u32) | 0o644,
        content: b"root:x:0:\nwheel:x:10:root\n",
    },
    BootstrapSeedFile {
        name: b"sudoers",
        mode: (S_IFREG as u32) | 0o440,
        content: b"root ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL:ALL) ALL\n",
    },
    BootstrapSeedFile {
        name: b"master.passwd",
        mode: (S_IFREG as u32) | 0o600,
        content: b"root:x:0:0:root:0:0:root:/root:/bin/bash\n",
    },
    BootstrapSeedFile {
        name: b"login.conf",
        mode: (S_IFREG as u32) | 0o644,
        content: b"",
    },
    BootstrapSeedFile {
        name: b"hosts",
        mode: (S_IFREG as u32) | 0o444,
        content: b"127.0.0.1\tlocalhost\n::1\t\tlocalhost\n",
    },
    BootstrapSeedFile {
        name: b"resolv.conf",
        mode: (S_IFREG as u32) | 0o444,
        content: b"nameserver 10.0.2.3\n",
    },
];

pub(crate) fn bootstrap_dir_mode(name: &[u8]) -> u32 {
    let perms = if name == b"tmp" {
        0o1777
    } else if name == b"proc" || name == b"sys" || name == b"initramfs" {
        0o555
    } else if name == b"root" {
        0o700
    } else {
        0o755
    };
    (S_IFDIR as u32) | perms
}

pub(crate) fn bootstrap_file_mode(mode: u32) -> u32 {
    mode
}

pub(crate) fn bootstrap_path_mode(path: &[u8]) -> u32 {
    if path == b"/" || path.is_empty() {
        return (S_IFDIR as u32) | 0o755;
    }
    let mut start = 0usize;
    for i in 0..path.len() {
        if path[i] == b'/' && i + 1 < path.len() {
            start = i + 1;
        }
    }
    bootstrap_dir_mode(&path[start..])
}

/// Structural anchors needed by the bootstrap FHS layout and the later
/// rootfs handoff.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct BootstrapLayout {
    /// Initial boot root (typically ramfs / initramfs).
    pub(crate) boot_root_mount: MountHandle,
    /// Covered real root mount once the backing root filesystem is ready.
    pub(crate) real_root_mount: MountHandle,
    /// Directory under the new root where the old root is attached.
    pub(crate) put_old_dir: VnodeHandle,
    /// Mountpoint where the future real root is grafted before pivot.
    pub(crate) new_root_dir: VnodeHandle,
    /// FHS scaffold directories that child mounts are reattached onto.
    pub(crate) etc_dir: VnodeHandle,
    pub(crate) dev_dir: VnodeHandle,
    pub(crate) proc_dir: VnodeHandle,
    pub(crate) sys_dir: VnodeHandle,
    pub(crate) tmp_dir: VnodeHandle,
    pub(crate) pipe_dir: VnodeHandle,
    pub(crate) initramfs_dir: VnodeHandle,
    /// Explicit bootstrap directory table.
    pub(crate) entries: [BootstrapDirEntry; BOOTSTRAP_ENTRY_CAP],
    pub(crate) entry_count: u8,
}

impl BootstrapLayout {
    pub(crate) const fn zeroed() -> Self {
        BootstrapLayout {
            boot_root_mount: MountHandle::INVALID,
            real_root_mount: MountHandle::INVALID,
            put_old_dir: VnodeHandle::INVALID,
            new_root_dir: VnodeHandle::INVALID,
            etc_dir: VnodeHandle::INVALID,
            dev_dir: VnodeHandle::INVALID,
            proc_dir: VnodeHandle::INVALID,
            sys_dir: VnodeHandle::INVALID,
            tmp_dir: VnodeHandle::INVALID,
            pipe_dir: VnodeHandle::INVALID,
            initramfs_dir: VnodeHandle::INVALID,
            entries: [const { BootstrapDirEntry::zeroed() }; BOOTSTRAP_ENTRY_CAP],
            entry_count: 0,
        }
    }
}
