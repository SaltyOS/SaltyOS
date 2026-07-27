//! Immutable terminal-completion record for process termination.
//!
//! An `ExitRecord` is populated exactly once, synchronously, when a
//! process transitions `Running → Zombie`. After that transition the
//! observer-side completion plane sees the terminal result regardless
//! of whether backend teardown (mmsrv deregister, VFS client exit,
//! rsrcsrv reclaim, CSpace deregister) has completed — those run
//! asynchronously via the teardown pump.
//!
//! Fields are treated as immutable after generation with two
//! exceptions: `sig_delivered` flips at the Zombie transition to
//! guarantee SIGCHLD is sent at most once, and `completion_consumed`
//! flips when an adapter consumes the terminal completion.
//!
//! Storage lives inline in [`Process`](super::proc_table::Process) to
//! share the proctab slot lifetime, but it is logically a separate
//! record — the live slot fields (`tcb_cap`, `vspace_cap`, etc.)
//! remain valid during backend teardown and must not be read by
//! waitpid, SIGCHLD delivery, or future non-POSIX completion adapters.
//!
//! SPDX-License-Identifier: GPL-2.0-only

#[derive(Clone, Copy)]
pub struct ExitRecord {
    pub exit_code: i32,
    pub exit_user_time_ns: u64,
    pub exit_system_time_ns: u64,
    /// True once SIGCHLD has been delivered to the parent (or skipped
    /// because the parent was gone / not catching). Ensures exactly
    /// one delivery per process lifetime.
    pub sig_delivered: bool,
    /// True once the terminal completion has been consumed by the
    /// current adapter (`waitpid` today). Gates the `Zombie → Reaped`
    /// transition (see `ProcessState`).
    pub completion_consumed: bool,
}

impl ExitRecord {
    pub const fn zeroed() -> Self {
        ExitRecord {
            exit_code: 0,
            exit_user_time_ns: 0,
            exit_system_time_ns: 0,
            sig_delivered: false,
            completion_consumed: false,
        }
    }
}
