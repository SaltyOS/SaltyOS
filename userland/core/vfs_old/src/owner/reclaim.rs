// SPDX-License-Identifier: GPL-2.0-only
//! Deferred reclaim — flight counting and periodic sweep.
//!
//! The owner loop calls `maybe_sweep` periodically to reclaim arena slots
//! that have completed the Active → Retired → Reclaimable lifecycle.
//!
//! Flight counting:
//! - Owner increments `vnode.flight_count` when dispatching a WorkItem.
//! - Owner decrements on Completion (via `FlightRelease`).
//! - A vnode cannot transition from Retired to Reclaimable while
//!   `flight_count > 0`.

use super::VfsState;

/// Sweep interval: run arena sweep every N dispatch cycles.
const SWEEP_INTERVAL: u64 = 64;

/// Low-watermark: also sweep if free count drops below this.
const FREE_LOW_WATERMARK: u32 = 16;

impl VfsState {
    /// Conditionally sweep arenas based on dispatch count or free-list
    /// pressure. Called once per owner loop iteration.
    pub(crate) fn maybe_sweep(&mut self) {
        let should = self.dispatch_count % SWEEP_INTERVAL == 0
            || self.vnodes.free_count() < FREE_LOW_WATERMARK
            || self.clients.free_count() < FREE_LOW_WATERMARK
            || self.open_objects.free_count() < FREE_LOW_WATERMARK
            || self.mount_ns.free_count() < FREE_LOW_WATERMARK
            || self.sockets.free_count() < FREE_LOW_WATERMARK
            || self.pipes.free_count() < FREE_LOW_WATERMARK
            || self.poll_waiters.free_count() < FREE_LOW_WATERMARK
            || self.epolls.free_count() < FREE_LOW_WATERMARK
            || self.shm_data.free_count() < FREE_LOW_WATERMARK
            || self.pending_ops.free_count() < FREE_LOW_WATERMARK;

        if should {
            // Pinned vnodes (mount roots, covered vnodes, client cwd
            // caches) stay alive across sweeps so structural identity
            // survives saltyfs cache pressure.
            self.vnodes.sweep_with(|v| v.is_pinned());
            self.mounts.sweep();
            self.clients.sweep();
            self.mount_ns.sweep();
            self.sockets.sweep();
            self.pipes.sweep();
            self.poll_waiters.sweep();
            self.epolls.sweep();
            self.shm_data.sweep();
            self.open_objects.sweep();
            self.pending_ops.sweep();
        }
    }
}
