// SPDX-License-Identifier: GPL-2.0-only
//! SaltyFS feature flag negotiation.
//!
//! At mount time, the SaltyFS server reports its superblock feature flags.
//! This module checks incompat/compat_ro flags and decides whether to mount,
//! mount read-only, or refuse.

/// Incompatible feature flags the VFS client understands.
const SALTYFS_INCOMPAT_XATTR: u32 = 1 << 0;
const SALTYFS_INCOMPAT_CASEFOLD: u32 = 1 << 1;
const SALTYFS_INCOMPAT_SUPPORTED: u32 = SALTYFS_INCOMPAT_XATTR | SALTYFS_INCOMPAT_CASEFOLD;

/// Compat-RO feature flags the VFS client understands.
const SALTYFS_COMPAT_RO_SUPPORTED: u32 = 0;

/// Mount-time feature flag result.
pub(super) enum FeatureResult {
    /// Mount read-write — all flags understood.
    ReadWrite,
    /// Mount read-only — unknown compat_ro flags present.
    ReadOnly,
    /// Refuse to mount — unknown incompat flags present.
    Reject,
}

/// Check feature flags returned by SALTYFS_MOUNT or SALTYFS_GETINFO.
pub(super) fn check_features(incompat_flags: u32, compat_ro_flags: u32) -> FeatureResult {
    // Unknown incompat bits → refuse.
    if (incompat_flags & !SALTYFS_INCOMPAT_SUPPORTED) != 0 {
        return FeatureResult::Reject;
    }
    // Unknown compat_ro bits → force read-only.
    if (compat_ro_flags & !SALTYFS_COMPAT_RO_SUPPORTED) != 0 {
        return FeatureResult::ReadOnly;
    }
    FeatureResult::ReadWrite
}
