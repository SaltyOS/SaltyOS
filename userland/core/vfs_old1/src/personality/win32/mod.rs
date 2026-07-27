// SPDX-License-Identifier: GPL-2.0-only
//! Win32 request surface.
//!
//! The new VFS is still POSIX-first. Keeping the module boundary now
//! avoids threading Win32 concerns back into the owner once that surface
//! starts to grow again.

pub(crate) mod casefold;
pub(crate) mod cwd_table;
pub(crate) mod dispatch;
pub(crate) mod drives;
pub(crate) mod path;
mod policy;
mod reserved;

use trona_kernel::core_types::*;
use uapi::*;

use crate::owner::VfsState;
use crate::server::types::{ClientHandle, PERS_WIN32};

pub(super) fn win32_client_or_oom(
    state: &mut VfsState,
    badge: u64,
    reply: *mut TronaMsg,
) -> Option<ClientHandle> {
    if let Some(cli_handle) = state.lookup_client(badge) {
        if let Some(client) = state.clients.get_mut(cli_handle) {
            client.personality = PERS_WIN32;
        }
        state.seed_win32_client_state(cli_handle);
        return Some(cli_handle);
    }

    let Some(cli_handle) = state.ensure_client(badge, PERS_WIN32) else {
        unsafe {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
        }
        return None;
    };
    Some(cli_handle)
}
