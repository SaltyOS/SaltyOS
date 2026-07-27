// SPDX-License-Identifier: GPL-2.0-only
//! POSIX request surface.

use trona_kernel::core_types::*;
use uapi::*;

use crate::owner::VfsState;
use crate::server::types::{ClientHandle, PERS_POSIX};

mod bulk;
pub(crate) mod dispatch;
mod fd;
mod mutate;
mod open;
mod path;
mod rw;
mod socket;

pub(super) fn posix_client_or_oom(
    state: &mut VfsState,
    badge: u64,
    reply: *mut TronaMsg,
) -> Option<ClientHandle> {
    if let Some(cli_handle) = state.lookup_client(badge) {
        return Some(cli_handle);
    }
    let Some(cli_handle) = state.ensure_client(badge, PERS_POSIX) else {
        unsafe {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
        }
        return None;
    };
    Some(cli_handle)
}
