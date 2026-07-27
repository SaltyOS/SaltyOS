// SPDX-License-Identifier: GPL-2.0-only
//
//! Typed VOP outcomes.
//!
//! VOPs do not encode backend-park control flow inside `VfsError`.
//! Instead, every VOP returns one of three explicit shapes:
//!
//! * `Ok(Ready(value))` — completed synchronously with a concrete
//!   result (in-memory file system, cache hit, error short-circuit
//!   that the VOP wants to surface as success).
//! * `Ok(Parked(handle))` — the VOP stamped a `PendingOp` and the
//!   caller must unwind to the owner reactor, leaving the reply
//!   slot to be consumed when the matching backend completion
//!   arrives.
//! * `Err(VfsError)` — domain failure (POSIX errno-class outcome).
//!
//! This separation keeps the async control flow legible at every
//! call site: the matcher distinguishes between "we have a value
//! now", "we have parked the work", and "we know the request
//! failed" — without overloading any of them onto an error
//! variant.

use crate::owner::pending::PendingOpHandle;

use super::error::{VfsError, VfsResult};

/// Successful VOP control-flow outcome.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum VopControl<T> {
    /// Completed synchronously with a concrete value.
    Ready(T),
    /// Parked on a reserved `PendingOp`. The caller must unwind to
    /// the owner reactor; the matching completion will resume
    /// through the saved reply slot.
    Parked(PendingOpHandle),
}

/// Full VOP result shape: explicit park vs domain failure.
pub(crate) type VopOutcome<T> = ::core::result::Result<VopControl<T>, VfsError>;

pub(crate) use VopControl::{Parked, Ready};

/// Helpers for collapsing or interrogating VOP outcomes at sync-
/// only call sites that cannot tolerate parking (in-memory fs,
/// cache-only fast paths, deterministic error injection in tests).
pub(crate) trait VopOutcomeExt<T> {
    /// Return the parked handle if this VOP yielded `Parked`.
    fn parked_handle(self) -> Option<PendingOpHandle>;

    /// Collapse the outcome to a plain `VfsResult<T>` by mapping
    /// `Parked` to the supplied error. Useful when a sync caller
    /// invokes a VOP that turns out to be backed by an async
    /// implementation — the caller wants a hard error rather than
    /// to thread a park back up.
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
