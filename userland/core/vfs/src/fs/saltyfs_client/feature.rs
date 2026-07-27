// SPDX-License-Identifier: GPL-2.0-only
//
//! SaltyFS backend-session feature negotiation.
//!
//! The daemon validates on-disk superblock incompat / compat_ro
//! flags before `BACKEND_OPEN_SESSION` succeeds. VFS validates the
//! transport features it needs for the per-mount-instance session:
//! async completions, incarnation sequences, and SHM transfer for
//! bulk directory / xattr traffic.

use trona_protocol::vfs::backend::{
    BACKEND_FEATURE_ASYNC_V1, BACKEND_FEATURE_INCARNATION_SEQ, BACKEND_FEATURE_SHM_TRANSFER,
};

/// Features required by the current SaltyFS VFS client.
const SALTYFS_BACKEND_REQUIRED: u64 =
    BACKEND_FEATURE_ASYNC_V1 | BACKEND_FEATURE_INCARNATION_SEQ | BACKEND_FEATURE_SHM_TRANSFER;

/// Mount-time feature flag result.
pub(crate) enum FeatureResult {
    /// Mount may proceed.
    Supported,
    /// Refuse to mount — the backend is missing a required
    /// session feature.
    Reject,
}

/// Check feature flags returned by `BACKEND_OPEN_SESSION`.
pub(crate) fn check_features(feature_bits: u64) -> FeatureResult {
    if (feature_bits & SALTYFS_BACKEND_REQUIRED) != SALTYFS_BACKEND_REQUIRED {
        return FeatureResult::Reject;
    }
    FeatureResult::Supported
}
