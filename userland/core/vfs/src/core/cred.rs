// SPDX-License-Identifier: GPL-2.0-only
//
//! VFS credential descriptor — personality-neutral.
//!
//! `VfsCred` is passed to permission-sensitive VOPs (access /
//! create / open / mutation paths). Each personality layer
//! translates its native credential shape (POSIX uid / gid /
//! groups, Win32 SID token, ...) into this structure once per
//! request and passes it immutably down the vop chain.

/// Maximum supplementary groups a credential can carry in-line
/// before the personality layer must fall back to a side-table
/// lookup. 32 covers every realistic POSIX login configuration
/// without bloating the per-request snapshot.
pub(crate) const VFS_MAX_GROUPS: usize = 32;

/// Personality-neutral credential descriptor. Never mutated by
/// vfs code — producers (the personality dispatch layer) fill it
/// once per request and the vop chain treats it as immutable.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VfsCred {
    /// Process id of the caller. Procfs / sysctlfs use it for
    /// per-process views (e.g. `/proc/self`).
    pub(crate) pid: u32,
    /// Real user id.
    pub(crate) uid: u32,
    /// Effective user id used for access checks.
    pub(crate) euid: u32,
    /// Real group id.
    pub(crate) gid: u32,
    /// Effective group id used for access checks.
    pub(crate) egid: u32,
    /// Number of populated entries in `groups`.
    pub(crate) ngroups: u8,
    /// Supplementary group list.
    pub(crate) groups: [u32; VFS_MAX_GROUPS],
}

impl VfsCred {
    /// Root credential — no restrictions. Used by boot-time
    /// filesystem setup before any user process exists.
    pub(crate) const fn root() -> Self {
        VfsCred {
            pid: 0,
            uid: 0,
            euid: 0,
            gid: 0,
            egid: 0,
            ngroups: 0,
            groups: [0; VFS_MAX_GROUPS],
        }
    }

    /// Zero-initialised credential, identical in shape to
    /// `root()` — kept as a separate constructor so call sites
    /// that fill the credential field-by-field from the inbound
    /// IPC record have a self-documenting starting point.
    pub(crate) const fn zeroed() -> Self {
        VfsCred {
            pid: 0,
            uid: 0,
            euid: 0,
            gid: 0,
            egid: 0,
            ngroups: 0,
            groups: [0; VFS_MAX_GROUPS],
        }
    }

    /// True when this credential belongs to root (real or
    /// effective uid 0).
    #[inline]
    pub(crate) fn is_root(&self) -> bool {
        self.uid == 0 || self.euid == 0
    }

    /// True when `gid` matches the effective gid or any
    /// supplementary group.
    pub(crate) fn in_group(&self, gid: u32) -> bool {
        if self.egid == gid {
            return true;
        }
        for i in 0..(self.ngroups as usize) {
            if self.groups[i] == gid {
                return true;
            }
        }
        false
    }
}
