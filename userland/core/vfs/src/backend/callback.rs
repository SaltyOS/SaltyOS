// SPDX-License-Identifier: GPL-2.0-only
//! Shared backend callback endpoint helpers.

static mut BACKEND_CALLBACK_EP_PREPARED: bool = false;

pub(crate) unsafe fn prepare_backend_callback_endpoint() -> bool {
    unsafe {
        if *(&raw const BACKEND_CALLBACK_EP_PREPARED) {
            return true;
        }

        // init provisions this endpoint via CreateEP=63 during spawn/restart.
        *(&raw mut BACKEND_CALLBACK_EP_PREPARED) = true;
        true
    }
}