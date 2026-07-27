// SPDX-License-Identifier: GPL-2.0-only
//! Typed VOP outcomes.
//!
//! VOPs no longer encode parked backend control flow inside
//! `VfsError`. Instead, a VOP returns either:
//! - `Ok(Ready(value))` for a completed result,
//! - `Ok(Parked(handle))` when the caller must unwind to the owner
//!   loop and resume later from a stamped `PendingOp`,
//! - `Err(VfsError)` for a real domain failure.

use crate::owner::pending::PendingOpHandle;

use super::error::{VfsError, VfsResult};

/// Successful VOP control-flow outcome.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum VopControl<T> {
    /// Completed synchronously with a concrete value.
    Ready(T),
    /// Parked on a reserved `PendingOp`.
    Parked(PendingOpHandle),
}

/// Full VOP result shape: explicit park vs domain failure.
pub(crate) type VopOutcome<T> = core::result::Result<VopControl<T>, VfsError>;

pub(crate) use VopControl::{Parked, Ready};

/// Helpers for collapsing or interrogating VOP outcomes at sync-only
/// call sites.
pub(crate) trait VopOutcomeExt<T> {
    /// Return the parked handle if this VOP yielded `Parked`.
    fn parked_handle(self) -> Option<PendingOpHandle>;

    /// Convert the outcome back to a plain `VfsResult<T>` by mapping
    /// `Parked` to the provided error.
    fn into_vfs_result_with_parked(self, parked_err: VfsError) -> VfsResult<T>;
}

impl<T> VopOutcomeExt<T> for VopOutcome<T> {
    #[inline]
    fn parked_handle(self) -> Option<PendingOpHandle> {
        match self {
            Ok(Parked(handle)) => Some(handle),
            _ => None,
        }
    }

    #[inline]
    fn into_vfs_result_with_parked(self, parked_err: VfsError) -> VfsResult<T> {
        match self {
            Ok(Ready(value)) => Ok(value),
            Ok(Parked(_)) => Err(parked_err),
            Err(err) => Err(err),
        }
    }
}
