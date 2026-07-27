// SPDX-License-Identifier: GPL-2.0-only
//! VFS credential descriptor — personality-neutral.
//!
//! `VfsCred` is passed to `VopVector::access` and other permission-sensitive
//! operations. Each personality layer translates its native credential shape
//! (POSIX uid/gid/groups, Win32 SID token, etc.) into this structure.

/// Maximum supplementary groups a credential can carry in-line.
pub(crate) const VFS_MAX_GROUPS: usize = 32;

/// Personality-neutral credential descriptor.
///
/// A snapshot of the calling thread's identity at the moment a VFS request
/// was received. Never mutated by VFS code — producers (dispatch layer)
/// fill it once per request and pass it immutably down the vop chain.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VfsCred {
    /// Process id of the caller. Used by procfs and similar filesystems
    /// that need caller identity for per-process views (e.g. /proc/self).
    pub(crate) pid: u32,
    /// Real user id.
    pub(crate) uid: u32,
    /// Effective user id (used for access checks).
    pub(crate) euid: u32,
    /// Real group id.
    pub(crate) gid: u32,
    /// Effective group id (used for access checks).
    pub(crate) egid: u32,
    /// Number of populated entries in `groups`.
    pub(crate) ngroups: u8,
    /// Supplementary group list.
    pub(crate) groups: [u32; VFS_MAX_GROUPS],
}

impl VfsCred {
    /// Root credential — no restrictions.
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

    /// Zero-initialized credential — used when filling from ClientState.
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

    /// Check whether this credential belongs to root (uid 0 or euid 0).
    #[inline]
    pub(crate) fn is_root(&self) -> bool {
        self.uid == 0 || self.euid == 0
    }

    /// Check whether `gid` is in the effective or supplementary group set.
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
