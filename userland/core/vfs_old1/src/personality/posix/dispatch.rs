// SPDX-License-Identifier: GPL-2.0-only
//! POSIX request dispatch fanout.

use trona_kernel::core_types::*;

use crate::owner::VfsState;

/// Try to dispatch one POSIX request.
pub(crate) fn dispatch_request(
    state: &mut VfsState,
    badge: u64,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) -> bool {
    super::path::dispatch_request(state, badge, msg, reply)
        || super::open::dispatch_request(state, badge, msg, reply)
        || super::bulk::dispatch_request(state, badge, msg, reply)
        || super::socket::dispatch_request(state, badge, msg, reply)
        || super::fd::dispatch_request(state, badge, msg, reply)
        || super::rw::dispatch_request(state, badge, msg, reply)
        || super::mutate::dispatch_request(state, badge, msg, reply)
}
