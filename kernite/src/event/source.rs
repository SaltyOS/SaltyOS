// SPDX-License-Identifier: GPL-2.0-only
//! Watchable source identification + watcher-list dispatch.
//!
//! `Watch::register` resolves its target via `(ObjectType,
//! *mut KernelObject)` and dispatches to the type's `WatcherList` on
//! state-flag publication. This module names the surface formally so
//! the watch / state / event-queue paths share a single vocabulary
//! for which kernel objects are watchable and which are not. Adding
//! a new watchable kernel object means: extend the `WatchableSource`
//! enum, extend `for_obj`, and extend `watcher_list_for` — and every
//! dispatch site picks up the new variant via exhaustive `match`.

use crate::cap::ObjectType;
use crate::event::watcher_list::WatcherList;

/// Set of kernel objects that publish `state_flags` and own a
/// `WatcherList`. Callers receive this from `WatchableSource::for_obj`
/// and use it as the dispatch key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchableSource {
    EventQueue,
    Timer,
    IrqHandler,
    MessagePipeSide,
    DataPipeSide,
}

impl WatchableSource {
    /// Resolve the watchable variant for an object type, or `None` if
    /// the object cannot be watched (caller-side caps, raw frames,
    /// CNodes, etc.). Used by `WATCH_REGISTER` validation and by the
    /// finalizer dispatch in `release_object` so non-watchable
    /// objects skip the watcher-list teardown path.
    #[inline]
    pub const fn for_obj(obj_type: ObjectType) -> Option<Self> {
        match obj_type {
            ObjectType::EventQueue => Some(Self::EventQueue),
            ObjectType::Timer => Some(Self::Timer),
            ObjectType::IrqHandler => Some(Self::IrqHandler),
            ObjectType::MessagePipe => Some(Self::MessagePipeSide),
            ObjectType::DataPipe => Some(Self::DataPipeSide),
            _ => None,
        }
    }

    /// `true` when the object's `state_flags` updates must traverse
    /// a side-private watcher list (Pipe sides) rather than the
    /// object header's watcher list directly.
    #[inline]
    pub const fn is_pipe_side(self) -> bool {
        matches!(self, Self::MessagePipeSide | Self::DataPipeSide)
    }
}

/// Resolve the `WatcherList` for a watchable object pointer.
///
/// Returns `core::ptr::null_mut()` when the pipe-side variants
/// observe a null `core` (peer side has already been finalized);
/// every other variant always returns a non-null pointer.
///
/// Callers obtain the `src` via `WatchableSource::for_obj`. The
/// dispatch is centralised here so every watcher-list lookup —
/// `WATCH_REGISTER` validation, `release_object` finalizer
/// teardown, state-flag publish — names the same path. A new
/// watchable variant is automatically caught at every callsite by
/// the exhaustive match.
///
/// # Safety
/// `obj` must point to a live kernel object of the type that `src`
/// was derived from (via `WatchableSource::for_obj`). Pipe-side
/// pointers must be the side-local `MessagePipe` / `DataPipe`
/// (not the shared core), with a still-valid `which_side` /
/// `core` pair.
#[inline]
pub(crate) unsafe fn watcher_list_for(
    src: WatchableSource,
    obj: *mut core::ffi::c_void,
) -> *mut WatcherList {
    unsafe {
        match src {
            WatchableSource::EventQueue => {
                &mut (*(obj as *mut crate::event::event_queue::EventQueue)).watcher_list
                    as *mut WatcherList
            }
            WatchableSource::Timer => {
                &mut (*(obj as *mut crate::event::timer::Timer)).watcher_list as *mut WatcherList
            }
            WatchableSource::IrqHandler => {
                &mut (*(obj as *mut crate::event::irq::IrqHandler)).watcher_list as *mut WatcherList
            }
            WatchableSource::MessagePipeSide => {
                let side = obj as *mut crate::ipc::message_pipe::MessagePipe;
                let core_ptr = (*side).core;
                if core_ptr.is_null() {
                    return core::ptr::null_mut();
                }
                if (*side).which_side == crate::ipc::message_pipe::SIDE_A {
                    &mut (*core_ptr).watchers_a as *mut WatcherList
                } else {
                    &mut (*core_ptr).watchers_b as *mut WatcherList
                }
            }
            WatchableSource::DataPipeSide => {
                let side = obj as *mut crate::ipc::data_pipe::DataPipe;
                let core_ptr = (*side).core;
                if core_ptr.is_null() {
                    return core::ptr::null_mut();
                }
                if (*side).which_side == crate::ipc::data_pipe::SIDE_A {
                    &mut (*core_ptr).watchers_a as *mut WatcherList
                } else {
                    &mut (*core_ptr).watchers_b as *mut WatcherList
                }
            }
        }
    }
}

/// Convenience wrapper that takes an `ObjectType` directly: returns
/// `null_mut()` for non-watchable types as well as for the pipe-side
/// `core == null` case. Use this from finalizer / disarm paths that
/// already hold an `ObjectType` rather than a `WatchableSource`.
///
/// # Safety
/// Same contract as [`watcher_list_for`].
#[inline]
pub(crate) unsafe fn watcher_list_for_obj_type(
    obj_type: ObjectType,
    obj: *mut core::ffi::c_void,
) -> *mut WatcherList {
    match WatchableSource::for_obj(obj_type) {
        Some(src) => unsafe { watcher_list_for(src, obj) },
        None => core::ptr::null_mut(),
    }
}
