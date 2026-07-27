// SPDX-License-Identifier: GPL-2.0-only
//! Character-device namespace metadata.
//!
//! The rebuilt VFS keeps device nodes structural: they are ordinary
//! bootstrap vnodes with `VT_CHR`, and their backend identity is encoded
//! directly in the vnode inode/generation pair instead of living in a
//! separate async registry.

use trona_posix::consts::S_IFCHR;

/// `/dev/console`.
pub(crate) const DN_CONSOLE: u8 = 0;
/// `/dev/null`.
pub(crate) const DN_NULL: u8 = 1;
/// `/dev/zero`.
pub(crate) const DN_ZERO: u8 = 2;
/// `/dev/fb0`.
pub(crate) const DN_FB0: u8 = 3;
/// `/dev/urandom`.
pub(crate) const DN_URANDOM: u8 = 4;
/// `/dev/ptmx`.
pub(crate) const DN_PTMX: u8 = 5;
/// `/dev/tty` controlling-terminal alias.
pub(crate) const DN_TTY_ALIAS: u8 = 6;
/// `/dev/pts/N` slave node.
pub(crate) const DN_PTY_SLAVE: u8 = 7;

const DEVICE_INO_TAG: u64 = 0x4445_0000_0000_0000;
const DEVICE_INO_TAG_MASK: u64 = 0xFFFF_0000_0000_0000;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct BootstrapDeviceSpec {
    pub(crate) name: &'static [u8],
    pub(crate) kind: u8,
    pub(crate) mode: u32,
}

pub(crate) const BOOTSTRAP_DEV_NODES: &[BootstrapDeviceSpec] = &[
    BootstrapDeviceSpec {
        name: b"console",
        kind: DN_CONSOLE,
        mode: (S_IFCHR as u32) | 0o666,
    },
    BootstrapDeviceSpec {
        name: b"null",
        kind: DN_NULL,
        mode: (S_IFCHR as u32) | 0o666,
    },
    BootstrapDeviceSpec {
        name: b"zero",
        kind: DN_ZERO,
        mode: (S_IFCHR as u32) | 0o666,
    },
    BootstrapDeviceSpec {
        name: b"fb0",
        kind: DN_FB0,
        mode: (S_IFCHR as u32) | 0o660,
    },
    BootstrapDeviceSpec {
        name: b"urandom",
        kind: DN_URANDOM,
        mode: (S_IFCHR as u32) | 0o666,
    },
    BootstrapDeviceSpec {
        name: b"ptmx",
        kind: DN_PTMX,
        mode: (S_IFCHR as u32) | 0o666,
    },
    BootstrapDeviceSpec {
        name: b"tty",
        kind: DN_TTY_ALIAS,
        mode: (S_IFCHR as u32) | 0o666,
    },
];

#[inline]
pub(crate) const fn device_inode(kind: u8, sub_id: u32) -> u64 {
    DEVICE_INO_TAG | ((kind as u64) << 32) | sub_id as u64
}

#[inline]
pub(crate) const fn decode_device_inode(inode: u64) -> Option<(u8, u32)> {
    if (inode & DEVICE_INO_TAG_MASK) != DEVICE_INO_TAG {
        return None;
    }
    Some((((inode >> 32) & 0xff) as u8, inode as u32))
}
