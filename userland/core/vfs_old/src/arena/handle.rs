// SPDX-License-Identifier: GPL-2.0-only
//! `Handle<T>` — stable, epoch-counted object identity.
//!
//! A handle is an 8-byte `(slot, epoch)` pair that identifies an object
//! in an [`Arena`]. The epoch counter detects use-after-free: a handle
//! is valid only when its epoch matches the slot's current epoch
//! in the arena. Stale handles are cheaply rejected without touching the
//! data itself.

use core::marker::PhantomData;

/// Stable identity token for an arena-managed object.
///
/// `Handle<T>` is `Copy`, `Eq`, and register-sized (8 bytes). It carries no
/// lifetime — validity is checked dynamically against the arena's slot
/// metadata.
///
/// `Clone` and `Copy` are implemented manually (not derived) to avoid an
/// implicit `T: Copy` bound. The handle is just two `u32` values — it does
/// not own or reference `T` in any way that requires `T` to be copyable.
#[repr(C)]
pub(crate) struct Handle<T> {
    slot: u32,
    epoch: u32,
    _marker: PhantomData<T>,
}

// Manual Clone/Copy — no T: Copy bound needed.
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
    /// Sentinel value representing "no object". Slot `u32::MAX` is never
    /// allocated by an arena.
    pub(crate) const INVALID: Self = Handle {
        slot: u32::MAX,
        epoch: 0,
        _marker: PhantomData,
    };

    /// Construct a handle from raw slot index and epoch.
    #[inline]
    pub(crate) const fn new(slot: u32, epoch: u32) -> Self {
        Handle {
            slot,
            epoch,
            _marker: PhantomData,
        }
    }

    #[inline]
    pub(crate) fn slot(self) -> u32 {
        self.slot
    }

    #[inline]
    pub(crate) fn epoch(self) -> u32 {
        self.epoch
    }

    /// Returns `true` if this handle is not the `INVALID` sentinel.
    /// Does NOT validate against an arena — use `Arena::is_alive` for that.
    #[inline]
    pub(crate) fn is_valid(self) -> bool {
        self.slot != u32::MAX
    }
}
