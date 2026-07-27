// SPDX-License-Identifier: GPL-2.0-only
//! Owner-level cancel walk.
//!
//! Single entry point that tears down a badge's deferred-op state and
//! every per-fileops waiter table keyed by client badge. Replaces
//! hand-paired `tty_wait::cancel_waiters_for_badge` +
//! `pending_ops::cancel_for_badge` call sequences that were prone to
//! drift — adding a new waiter table now means changing this one
//! function instead of auditing every lifecycle site.

use crate::owner::VfsState;
use crate::owner::pending_ops::{self, CancelDisposition};

/// Owner-level cancel for `badge`. `tty_wait::cancel_waiters_for_badge`
/// already chains into `inet_wait::` and `socket_wait::` badge cancels;
/// `pending_ops::cancel_for_badge` walks the deferred-op table.
///
/// # Safety
///
/// Owner-thread only. Must be called between IPC dispatches; must not
/// be called from a worker.
pub(crate) unsafe fn vfs_cancel_for_badge(
    state: &mut VfsState,
    badge: u64,
    disposition: CancelDisposition,
) {
    unsafe {
        crate::fileops::tty_wait::cancel_waiters_for_badge(state, badge);
    }
    let _ = unsafe { pending_ops::cancel_for_badge(badge, disposition) };
}
