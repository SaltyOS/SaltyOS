//! Backend teardown bookkeeping constants.
//!
//! Every process that enters `ProcessState::Zombie` (or an aborted
//! `launch_pending` spawn) has backend teardown work pending: personality
//! pre-teardown (Win32 provider exit), mmsrv deregister, rsrcsrv
//! reclaim, auxiliary thread drop, CSpace deregister, personality
//! post-teardown (VFS client exit). These steps run asynchronously
//! via the teardown pump in `lifecycle::exit::process_pending_teardowns`
//! so the observer-visible Zombie transition is not gated on any of them
//! succeeding.
//!
//! The per-step completion state lives inline on `Process`
//! (`teardown_steps_done`, `teardown_abandoned`, retry deadlines) —
//! this module defines only the bitmap constants and timing budget so
//! there is a single source of truth.
//!
//! ## Abandoned ≠ Complete
//!
//! If a step keeps failing past `TEARDOWN_HARD_DEADLINE_NS`, the job
//! is marked `teardown_abandoned = true`, which allows the slot to be
//! recycled but leaves the `teardown_steps_done` bits UNSET for the
//! steps that never ran. Backend services keyed by the process badge
//! (mmsrv client registry, VFS client state, rsrcsrv owner map) may
//! therefore retain stale entries — each backend is responsible for
//! existence-checking on badge reuse.
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// Personality `pre_teardown` — Win32 provider exit / POSIX preamble.
pub const STEP_PRE: u8 = 0b0000_0001;
/// `mmsrv deregister` — writeback pending pages and unregister client.
pub const STEP_MMSRV: u8 = 0b0000_0010;
/// `rsrcsrv reclaim_owner` — release per-owner caps tracked in rsrcsrv.
pub const STEP_RSRCSRV: u8 = 0b0000_0100;
/// Drop auxiliary threads (pthreads / win32 thread shim).
pub const STEP_THREADS: u8 = 0b0000_1000;
/// `cspace` step — historically removed the badge from procmgr's
/// CSpace-expand client map; that map is gone, but the step bit is kept
/// so existing teardown progress masks remain stable. The step now
/// completes as a no-op.
pub const STEP_CSPACE: u8 = 0b0001_0000;
/// Personality `post_teardown` — VFS client exit etc.
pub const STEP_POST: u8 = 0b0010_0000;

/// All steps complete.
pub const STEP_ALL: u8 =
    STEP_PRE | STEP_MMSRV | STEP_RSRCSRV | STEP_THREADS | STEP_CSPACE | STEP_POST;

/// Retry spacing when a step fails transiently (only mmsrv retries in
/// practice; other steps are local and always succeed first try).
pub const TEARDOWN_RETRY_INTERVAL_NS: u64 = 100_000_000; // 100 ms

/// Hard deadline: a teardown job that is still incomplete this long
/// after the Zombie transition is marked `abandoned` so the slot can
/// be recycled.  Backend-side stale state is an acceptable trade-off
/// against permanent slot leaks when a downstream service wedges.
pub const TEARDOWN_HARD_DEADLINE_NS: u64 = 10_000_000_000; // 10 s

/// Helper: is a `steps_done` bitmap fully satisfied?
#[inline]
pub fn is_complete(steps_done: u8) -> bool {
    steps_done & STEP_ALL == STEP_ALL
}
