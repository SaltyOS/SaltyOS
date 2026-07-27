// SPDX-License-Identifier: GPL-2.0-only
//! `Handle<T>` — stable, epoch-counted object identity.
//!
//! Namespace objects are referenced by `(slot, epoch)` handles instead of
//! raw pointers. The slot identifies the slab entry; the epoch prevents a
//! recycled slot from impersonating an older object.

use core::marker::PhantomData;

/// Stable identity token for an arena-managed object.
#[repr(C)]
pub(crate) struct Handle<T> {
    slot: u32,
    epoch: u32,
    _marker: PhantomData<T>,
}

impl<T> Clone for Handle<T> {
    #[inline]
    fn clone(&self) -> Self {
        Handle {
            slot: self.slot,
            epoch: self.epoch,
            _marker: PhantomData,
        }
    }
}

impl<T> Copy for Handle<T> {}

impl<T> PartialEq for Handle<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.slot == other.slot && self.epoch == other.epoch
    }
}

impl<T> Eq for Handle<T> {}

impl<T> Handle<T> {
    /// Sentinel representing "no object".
    pub(crate) const INVALID: Self = Handle {
        slot: u32::MAX,
        epoch: 0,
        _marker: PhantomData,
    };

    #[inline]
    pub(crate) const fn new(slot: u32, epoch: u32) -> Self {
        Handle {
            slot,
            epoch,
            _marker: PhantomData,
        }
    }

    #[inline]
    pub(crate) const fn slot(self) -> u32 {
        self.slot
    }

    #[inline]
    pub(crate) const fn epoch(self) -> u32 {
        self.epoch
    }

    /// Zeroed handles are invalid because arena epochs start at 1.
    #[inline]
    pub(crate) const fn is_valid(self) -> bool {
        self.slot != u32::MAX && self.epoch != 0
    }
}
