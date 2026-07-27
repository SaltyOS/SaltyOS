// SPDX-License-Identifier: GPL-2.0-only
//! Shared backend callback endpoint helpers.
//!
//! The "prepared" flag lives on `VfsState` so every backend-bootstrap
//! state bit is single-sourced; there are no module-local `static mut`
//! toggles. `prepare_backend_callback_endpoint` takes `&mut VfsState`
//! and flips `state.backend_callback_prepared` once the local-role
//! lookup returns a live cap.

use crate::owner::VfsState;

const BACKEND_CALLBACK_LOCAL_KEY: &[u8] = b"vfs:backend_callback";

#[inline]
pub(crate) fn backend_callback_ep() -> u64 {
    trona_runtime::client::caps::local_by_name(BACKEND_CALLBACK_LOCAL_KEY)
}

/// Resolve the shared backend callback EP the first time it is
/// consulted. Idempotent: once a live cap has been observed the
/// `state.backend_callback_prepared` flag stays set and subsequent
/// calls return in O(1). Returns `true` when the cap is available.
pub(crate) fn prepare_backend_callback_endpoint(state: &mut VfsState) -> bool {
    if state.backend_callback_prepared {
        return backend_callback_ep() != 0;
    }
    if backend_callback_ep() == 0 {
        return false;
    }
    state.backend_callback_prepared = true;
    true
}
